import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'node:url';

const __dirname = import.meta.dirname || path.dirname(fileURLToPath(import.meta.url));

const properties = {};

for (const file of await fs.readdir(__dirname)) {
    const parsed = path.parse(file);
    if (parsed.ext === '.json') {
        const filePath = path.join(__dirname, file);
        properties[parsed.name] = JSON.parse(await fs.readFile(filePath, 'utf-8'));
    }
}

console.log("properties", Object.keys(properties));

export default properties;
