// Gera o index.html publicado a partir do index.fonte.html, com os cases cifrados.
//
//   node build/cifrar.mjs
//
// Pede a senha no terminal (duas vezes) e nunca a grava em lugar nenhum.
// O trecho entre CIFRAR:INICIO e CIFRAR:FIM vira um bloco AES-GCM 256,
// com a chave derivada da senha por PBKDF2-SHA256.

import { readFile, writeFile } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const RAIZ = join(dirname(fileURLToPath(import.meta.url)), '..');
const FONTE = join(RAIZ, 'index.fonte.html');
const SAIDA = join(RAIZ, 'index.html');
const INICIO = /<!-- CIFRAR:INICIO[^>]*-->/;
const FIM = '<!-- CIFRAR:FIM -->';
// OWASP 2023 para PBKDF2-SHA256; leva cerca de meio segundo num celular
const ITERACOES = 600000;

// Senha digitada sem eco. CIFRA_SENHA no ambiente serve só para teste automatizado.
function perguntarSenha(pergunta) {
  return new Promise(resolve => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = texto => { if (texto.includes(pergunta)) process.stdout.write(texto); };
    rl.question(pergunta, resposta => { rl.close(); process.stdout.write('\n'); resolve(resposta); });
  });
}

async function obterSenha() {
  if (process.env.CIFRA_SENHA) return process.env.CIFRA_SENHA;
  const senha = await perguntarSenha('Senha do portfólio: ');
  const confirmacao = await perguntarSenha('Repita a senha: ');
  if (senha !== confirmacao) throw new Error('As senhas não conferem. Nada foi gerado.');
  if (senha.length < 10) throw new Error('Use pelo menos 10 caracteres. Nada foi gerado.');
  return senha;
}

const base64 = bytes => Buffer.from(bytes).toString('base64');

const fonte = await readFile(FONTE, 'utf8');
const inicio = fonte.match(INICIO);
const fim = fonte.indexOf(FIM);
if (!inicio || fim === -1 || fim < inicio.index) {
  throw new Error('Marcadores CIFRAR:INICIO / CIFRAR:FIM não encontrados no index.fonte.html.');
}
const claro = fonte.slice(inicio.index + inicio[0].length, fim);

const senha = await obterSenha();
const sal = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(senha), 'PBKDF2', false, ['deriveKey']);
const chave = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt: sal, iterations: ITERACOES, hash: 'SHA-256' },
  base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const cifrado = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, chave, new TextEncoder().encode(claro));

const pacote = { v: 1, it: ITERACOES, sal: base64(sal), iv: base64(iv), dados: base64(new Uint8Array(cifrado)) };
const bloco = `<script type="application/json" id="cases-cifrados">${JSON.stringify(pacote)}</script>`;
const publicado = fonte.slice(0, inicio.index) + bloco + fonte.slice(fim + FIM.length);

// trava de segurança: nada dos cases pode sobrar em texto claro
if (/class="case-page"|class="case-toc"/.test(publicado)) {
  throw new Error('Sobrou conteúdo de case em texto claro. Nada foi gerado.');
}

await writeFile(SAIDA, publicado);
console.log(`index.html gerado: ${Math.round(claro.length / 1024)} KB de cases cifrados.`);
