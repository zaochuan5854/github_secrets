import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import mime from 'mime-types';
import { encryptFile } from '../core/crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const webDataDir = path.join(__dirname, '../web/data');

const [, , entryName, filePath, password] = process.argv;
if (!entryName || !filePath || !password) {
    console.error("Usage: bun src/cli/encrypt.ts <entryName> <filePath> <password>");
    process.exit(1);
}

async function main(entryName: string, filePath: string, password: string, dataDir: string) {
    if (!fs.existsSync(filePath)) throw new Error("File not found: " + filePath);
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }
    const fileData = fs.readFileSync(filePath);
    const fileName = path.basename(filePath);
    const mimeType = mime.lookup(filePath) || "application/octet-stream";

    // 暗号化
    const encrypted = await encryptFile(new Uint8Array(fileData), { name: fileName, type: mimeType }, password);

    // インデックスへの保存
    const indexPath = path.join(dataDir, 'index.json');
    let indexObject: any = {};
    if (fs.existsSync(indexPath)) {
        indexObject = JSON.parse(fs.readFileSync(indexPath, 'utf-8'));
    }
    const id = (indexObject["nextId"] || 1);
    indexObject["nextId"] = id + 1;
    let indexes = indexObject["indexes"] || {};
    if (indexes[entryName]) {
        console.error(`Entry "${entryName}" already exists.`);
        process.exit(1);
    }
    indexes[entryName] = id;
    indexObject["indexes"] = indexes;
    fs.writeFileSync(indexPath, JSON.stringify(indexObject, null, 2), 'utf-8');

    // 暗号化データの保存
    const encryptedPath = path.join(dataDir, `${id}.json`);
    fs.writeFileSync(encryptedPath, JSON.stringify(encrypted, null, 2), 'utf-8');

    console.log(`File encrypted and saved under entry "${entryName}" in ${encryptedPath}`);
}

main(entryName, filePath, password, webDataDir);