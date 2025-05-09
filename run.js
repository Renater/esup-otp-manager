#!/usr/bin/env node
import './server/server.js';

process.on('SIGINT', function() {
    process.exit(0);
});
