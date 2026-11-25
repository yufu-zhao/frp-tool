// tls-proxy 是一个仅依赖 Go 标准库的单文件静态 TLS 终止反向代理。
//
// 它是「穿透工作台」的服务器托管 TLS 实例：临时持有 80/443，把 HTTPS 流量
// 反代到本机高端口的 frps vhost（如 127.0.0.1:8080），并应答 ACME http-01
// 验证。所有状态（证书、日志、配置）都由外部 JSON 配置指定，程序本身不写
// 任何系统路径，便于一键、零残留卸载。
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// version 与 src/main/tls-proxy.ts 中的 TLS_PROXY_VERSION 保持一致，安装时
// 通过 `-version` 校验上传的二进制确实是本程序。
const version = "1.0.0"

// Config 是外部写入的 JSON 配置，字段全部为必填（除空值外会在启动时校验）。
type Config struct {
	HTTPAddr     string `json:"httpAddr"`     // 例如 ":80"
	HTTPSAddr    string `json:"httpsAddr"`    // 例如 ":443"
	CertFile     string `json:"certFile"`     // 证书 PEM（fullchain）
	KeyFile      string `json:"keyFile"`      // 私钥 PEM
	Upstream     string `json:"upstream"`     // 例如 "http://127.0.0.1:8080"
	ChallengeDir string `json:"challengeDir"` // 存放 acme 挑战 token 文件的目录
	LogFile      string `json:"logFile"`      // 结构化日志追加写入的文件
}

func main() {
	var (
		configPath  = flag.String("config", "", "JSON 配置文件路径（必填）")
		showVersion = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *configPath == "" {
		fatal("缺少 -config 参数：必须通过 -config 指定 JSON 配置文件路径")
	}
	if err := run(*configPath); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	fmt.Fprintf(os.Stderr, "tls-proxy: %s\n", message)
	os.Exit(1)
}

// logger 把结构化 JSON 行同时写入日志文件与 stdout，带互斥锁避免并发写交错。
type logger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *logger) write(level, message string, fields map[string]any) {
	record := map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
		"level": level,
		"msg":   message,
	}
	for key, value := range fields {
		record[key] = value
	}
	encoded, _ := json.Marshal(record)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(encoded, '\n'))
}

func (l *logger) info(message string, fields map[string]any)  { l.write("info", message, fields) }
func (l *logger) error(message string, fields map[string]any) { l.write("error", message, fields) }

// statusRecorder 包装 ResponseWriter 记录状态码，同时保留 Hijacker / Flusher /
// Unwrap，确保 httputil.ReverseProxy 的 WebSocket Upgrade 透传不被破坏。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, errors.New("底层 ResponseWriter 不支持 Hijack")
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func accessLog(lg *logger, listener string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		lg.info("access", map[string]any{
			"listener": listener,
			"host":     r.Host,
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   status,
			"remote":   clientIP(r.RemoteAddr),
		})
	})
}

func run(configPath string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件 %q 失败：%w", configPath, err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("解析配置文件失败：%w", err)
	}
	if cfg.HTTPAddr == "" || cfg.HTTPSAddr == "" {
		return errors.New("配置缺少 httpAddr / httpsAddr")
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return errors.New("配置缺少 certFile / keyFile")
	}
	if cfg.Upstream == "" || cfg.ChallengeDir == "" || cfg.LogFile == "" {
		return errors.New("配置缺少 upstream / challengeDir / logFile")
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil || upstream.Host == "" || (upstream.Scheme != "http" && upstream.Scheme != "https") {
		return fmt.Errorf("upstream 无效：%q", cfg.Upstream)
	}

	// 证书/私钥不存在或无效时明确报错退出，绝不「带病启动」。
	first, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("加载证书/私钥失败（cert=%q key=%q）：%w", cfg.CertFile, cfg.KeyFile, err)
	}

	logFile, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("打开日志文件 %q 失败：%w", cfg.LogFile, err)
	}
	defer logFile.Close()
	lg := &logger{w: io.MultiWriter(logFile, os.Stdout)}
	lg.info("starting", map[string]any{
		"version":  version,
		"http":     cfg.HTTPAddr,
		"https":    cfg.HTTPSAddr,
		"upstream": upstream.Host,
		"cert":     cfg.CertFile,
	})

	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	// 证书热重载：定时 stat 证书/私钥的 mtime 与 size，变化即原子替换，
	// 续期后（文件被原子替换）无需重启即可生效。不引入任何第三方库。
	var certValue atomic.Value // 存储 *tls.Certificate
	certValue.Store(&first)
	certMtime, certSize := fileStamp(cfg.CertFile)
	keyMtime, keySize := fileStamp(cfg.KeyFile)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cm, cs := fileStamp(cfg.CertFile)
				km, ks := fileStamp(cfg.KeyFile)
				if cm == certMtime && cs == certSize && km == keyMtime && ks == keySize {
					continue
				}
				pair, loadErr := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
				if loadErr != nil {
					// 续期过程中可能短暂读到半成品，保留旧证书并下个周期重试。
					lg.error("certificate reload failed", map[string]any{"error": loadErr.Error()})
					continue
				}
				certValue.Store(&pair)
				certMtime, certSize, keyMtime, keySize = cm, cs, km, ks
				lg.info("certificate reloaded", nil)
			}
		}
	}()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certValue.Load().(*tls.Certificate), nil
		},
	}

	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// 不改 r.Host，保留客户端原始 Host 头；仅改 URL 指向本机上游。
			r.URL.Scheme = upstream.Scheme
			r.URL.Host = upstream.Host
			r.RequestURI = ""
			r.Header.Set("X-Real-IP", clientIP(r.RemoteAddr))
			r.Header.Set("X-Forwarded-Proto", "https")
			// X-Forwarded-For 由 httputil.ReverseProxy 在 Director 之后自动追加。
		},
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     false,
			ResponseHeaderTimeout: 0,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, proxyErr error) {
			lg.error("proxy error", map[string]any{
				"error": proxyErr.Error(),
				"host":  r.Host,
				"path":  r.URL.Path,
			})
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	// httputil.ReverseProxy 原生支持 HTTP/1.1 Upgrade：当上游返回 101 时
	// 会 hijack 客户端连接并双向隧道透传，因此 WebSocket 可直接使用。

	httpsServer := &http.Server{
		Handler:           accessLog(lg, "https", proxy),
		ReadHeaderTimeout: 15 * time.Second,
		// 空（非 nil）map 显式禁用 HTTP/2，确保只走 HTTP/1.1（WebSocket 兼容）。
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	httpServer := &http.Server{
		Handler:           accessLog(lg, "http", challengeHandler(cfg)),
		ReadHeaderTimeout: 15 * time.Second,
	}

	httpsListener, err := net.Listen("tcp", cfg.HTTPSAddr)
	if err != nil {
		return fmt.Errorf("监听 %q 失败（低于 1024 的端口需要 cap_net_bind_service 或 root）：%w", cfg.HTTPSAddr, err)
	}
	httpListener, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		httpsListener.Close()
		return fmt.Errorf("监听 %q 失败（低于 1024 的端口需要 cap_net_bind_service 或 root）：%w", cfg.HTTPAddr, err)
	}

	serveErr := make(chan error, 2)
	go func() {
		lg.info("https listening", map[string]any{"addr": cfg.HTTPSAddr})
		if serveError := httpsServer.Serve(tls.NewListener(httpsListener, tlsConfig)); serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
			serveErr <- serveError
		}
	}()
	go func() {
		lg.info("http listening", map[string]any{"addr": cfg.HTTPAddr})
		if serveError := httpServer.Serve(httpListener); serveError != nil && !errors.Is(serveError, http.ErrServerClosed) {
			serveErr <- serveError
		}
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		lg.info("shutting down", map[string]any{"signal": "SIGTERM/SIGINT"})
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = httpsServer.Shutdown(shutdownCtx) }()
	go func() { defer wg.Done(); _ = httpServer.Shutdown(shutdownCtx) }()
	wg.Wait()
	lg.info("stopped", nil)
	return nil
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// challengeHandler 处理 80 端口：仅 /.well-known/acme-challenge/<token> 从
// challengeDir 读取同名文件返回 text/plain，其余请求 301 跳转到 https。
func challengeHandler(cfg Config) http.Handler {
	const prefix = "/.well-known/acme-challenge/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, prefix) {
			token := strings.TrimPrefix(r.URL.Path, prefix)
			// token 必须是纯 base64url 字符，杜绝路径穿越。
			if tokenPattern.MatchString(token) {
				data, readErr := os.ReadFile(filepath.Join(cfg.ChallengeDir, token))
				if readErr == nil {
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(data)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// fileStamp 返回 (mtime UnixNano, size)，用于检测证书文件是否被替换。
func fileStamp(path string) (int64, int64) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0
	}
	return info.ModTime().UnixNano(), info.Size()
}
