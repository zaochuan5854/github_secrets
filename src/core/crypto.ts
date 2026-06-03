// 暗号化結果
export interface EncryptResult {
    cipherBase64: string;
    saltBase64: string;
    ivBase64: string;
}

// メタデータ（ファイル名、MIMEタイプ）の型定義
export interface FileMeta {
    name: string;
    type: string;
}

// 復号結果
export interface DecryptResult {
    meta: FileMeta;
    fileBytes: Uint8Array;
}

// ArrayBufferをBase64に変換（環境に依存しない実装）
export function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);

  // Bun / Node.js 環境
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }

  // ブラウザ環境
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i] || 0);
  }
  
  return window.btoa(binary);
}

// Base64をUint8Arrayに変換
export function base64ToUint8Array(base64: string): Uint8Array {
    // Bun / Node.js 環境
    if (typeof Buffer !== 'undefined') {
        const buf = Buffer.from(base64, 'base64');
        return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
    
    // ブラウザ環境
    if (typeof window !== 'undefined' && window.atob) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
    
    throw new Error('Unsupported environment: Neither Buffer nor window.atob is available.');
}
/**
 * 共通暗号化ロジック
 */
export async function encryptFile(fileBytes: Uint8Array, meta: FileMeta, password: string): Promise<EncryptResult> {
    const encoder = new TextEncoder();
    const metaData = encoder.encode(JSON.stringify(meta));

    // パッキング: [メタデータ長(4B)] + [メタデータ] + [ファイル本体]
    const combinedBuffer = new Uint8Array(4 + metaData.length + fileBytes.length);
    const view = new DataView(combinedBuffer.buffer);
    view.setUint32(0, metaData.length);
    combinedBuffer.set(metaData, 4);
    combinedBuffer.set(fileBytes, 4 + metaData.length);

    // 鍵生成と暗号化
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const passwordKey = await crypto.subtle.importKey(
        "raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    const aesKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 600000, hash: "SHA-256" },
        passwordKey, { name: "AES-GCM", length: 256 }, false, ["encrypt"]
    );

    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 },
        aesKey,
        combinedBuffer
    );

    return {
        cipherBase64: bufferToBase64(encryptedBuffer),
        saltBase64: bufferToBase64(salt),
        ivBase64: bufferToBase64(iv)
    };

}

/**
 * 共通復号ロジック
 */
export async function decryptFile(encryptoResult: EncryptResult, password: string): Promise<DecryptResult> {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const encryptedBuffer = base64ToUint8Array(encryptoResult.cipherBase64);
    const salt = base64ToUint8Array(encryptoResult.saltBase64);
    const iv = base64ToUint8Array(encryptoResult.ivBase64);

    const passwordKey = await crypto.subtle.importKey(
        "raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    const aesKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt as BufferSource, iterations: 600000, hash: "SHA-256" },
        passwordKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv, tagLength: 128 } as AesGcmParams,
        aesKey,
        encryptedBuffer as BufferSource
    );

    const decryptedBytes = new Uint8Array(decryptedBuffer);
    const view = new DataView(decryptedBytes.buffer);
    
    const metaLength = view.getUint32(0);
    const metaBytes = decryptedBytes.slice(4, 4 + metaLength);
    const meta: FileMeta = JSON.parse(decoder.decode(metaBytes));
    const fileBytes = decryptedBytes.slice(4 + metaLength);

    return { meta, fileBytes };
}