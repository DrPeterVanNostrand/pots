# Proof-of-Transient-Space

### About

Proof-of-Space from a hard-to-pebble stacked bipartite expander.

Paper: ["Proof of Space from Stacked Bipartite Graphs"](https://pdfs.semanticscholar.org/afce/9f024104d6753120ace2a4193d296bc24f3a.pdf)

### Run in the Browser

```
$ git clone https://github.com/DrPeterVanNostrand/pots.git
$ cd pots
$ wasm-pack build
$ cd pkg && npm link && cd ..
$ cd site && npm install && npm link pots

# Run the Webpack dev-server on port 8080.
$ npm run start
```

Go to `127.0.0.1:8080` in your browser, open the console to view the proof logs.

### Run from a NodeJS Script

```
$ git clone https://github.com/DrPeterVanNostrand/pots.git
$ cd pots
$ wasm-pack build --target=nodejs
$ cd pkg
$ node
> const pots = require("./pots.js");
> pots.main();
```
