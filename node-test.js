
// import { createServer } from 'node:http';
const { createServer } = require('node:http');
(async () => {
    const server = createServer((request, response) => {
        const token = decodeURIComponent((request.url ?? '').split('/').at(-1) ?? '');
        console.log("token:", token)
        // const value = tokens.get(token);
        // if (!request.url?.startsWith('/.well-known/acme-challenge/') || !value) {
        //     response.writeHead(404).end('not found');
        //     return;
        // }
        response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' }).end("value");
    });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            server.removeListener('error', reject);
            resolve();
        });
    });
    console.log(server.address())

})()