import test from 'ava';
import { execFile } from 'child_process';
// tslint:disable-next-line:no-submodule-imports
// import * as util from 'util'; // No longer needed after runCLI refactor
// tslint:disable-next-line:no-submodule-imports
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

// const execFileAsync = util.promisify(execFile); // Replaced with manual Promise for stdin control

// Path to the compiled CLI script
// __dirname in an ES module context is the directory of the current file.
// The compiled cli.spec.mjs will be in build/main/cli/, and cli.mjs will be in the same directory.
const cliPath = path.resolve(__dirname, './cli.mjs');

interface CLIResponse {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

async function runCLI(
  args: string[],
  stdinData?: string
): Promise<CLIResponse> {
  return new Promise((resolve) => {
    const child = execFile('node', [cliPath, ...args], {
      env: { ...process.env, AESCRYPT_PASSWORD: '' }, // Ensure env password is not set
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => (stdout += data.toString()));
    child.stderr?.on('data', (data) => (stderr += data.toString()));

    if (stdinData) {
      child.stdin?.write(stdinData);
    }
    child.stdin?.end(); // End stdin to signal no more input or that it's intentionally empty

    child.on('close', (code) => {
      resolve({ stdout, stderr, exitCode: code });
    });
    child.on('error', (err: any) => {
      // Catch spawn errors etc.
      // Ensure stderr and stdout are captured from the error object if available
      stderr += err.stderr || '';
      stdout += err.stdout || '';
      resolve({
        stdout,
        stderr,
        exitCode: err.code === undefined ? 1 : err.code,
      });
    });
  });
}

test('CLI: should show error if no operation is specified', async (t) => {
  const { stderr, exitCode } = await runCLI([]);
  t.is(exitCode, 1, 'Should exit with code 1');
  t.true(
    stderr.includes('Error: -e or -d not specified'),
    'Stderr should contain specific error message'
  );
});

test('CLI: should show error if both -e and -d are specified', async (t) => {
  const { stderr, exitCode } = await runCLI(['-e', '-d', 'somefile.txt']);
  t.is(exitCode, 1, 'Should exit with code 1');
  t.true(
    stderr.includes('Error: only specify one of -d or -e'),
    'Stderr should contain specific error message'
  );
});

test('CLI: should show error when decrypting non-.aes file (not stdin)', async (t) => {
  const { stderr, exitCode } = await runCLI([
    '-d',
    '-p',
    'test',
    'somefile.txt',
  ]);
  t.is(exitCode, 1, 'Should exit with code 1');
  t.true(
    stderr.includes(
      "Error: input file for decryption 'somefile.txt' doesn't end in .aes"
    ),
    'Stderr should contain specific error message'
  );
});

test('CLI: should show error for output file with multiple inputs', async (t) => {
  const { stderr, exitCode } = await runCLI([
    '-e',
    '-p',
    'test',
    '-o',
    'output.aes',
    'file1.txt',
    'file2.txt',
  ]);
  t.is(exitCode, 1, 'Should exit with code 1');
  t.true(
    stderr.includes(
      'Error: A single output file may not be specified with multiple input files.'
    ),
    'Stderr should contain specific error message'
  );
});

test('CLI: should show error for stdin with multiple inputs', async (t) => {
  const { stderr, exitCode } = await runCLI([
    '-e',
    '-p',
    'test',
    '-',
    'file1.txt',
  ]);
  t.is(exitCode, 1, 'Should exit with code 1');
  t.true(
    stderr.includes(
      'Error: STDIN may not be specified with multiple input files.'
    ),
    'Stderr should contain specific error message'
  );
});

// Integration test: Successful encryption and decryption
test('CLI: should encrypt and then decrypt a file successfully', async (t) => {
  const tempDir = await fs.mkdtemp(
    path.join(os.tmpdir(), 'aescrypt-cli-test-')
  );
  const originalFilePath = path.join(tempDir, 'original.txt');
  const encryptedFilePath = path.join(tempDir, 'original.txt.aes');
  const decryptedFilePath = path.join(tempDir, 'decrypted.txt');
  const originalContent =
    'This is a test content for CLI encryption and decryption!';
  const password = 'supersecretpassword';

  await fs.writeFile(originalFilePath, originalContent);

  // Encrypt
  const encResult = await runCLI([
    '-e',
    '-p',
    password,
    '-o',
    encryptedFilePath,
    originalFilePath,
  ]);
  t.is(encResult.exitCode, 0, `Encryption failed: ${encResult.stderr}`);
  // if (encResult.exitCode !== 0) {
  //   console.error('Encryption stderr:', encResult.stderr);
  //   console.error('Encryption stdout:', encResult.stdout);
  // }

  // Decrypt
  const decResult = await runCLI([
    '-d',
    '-p',
    password,
    '-o',
    decryptedFilePath,
    encryptedFilePath,
  ]);
  t.is(decResult.exitCode, 0, `Decryption failed: ${decResult.stderr}`);
  //  if (decResult.exitCode !== 0) {
  //   console.error('Decryption stderr:', decResult.stderr);
  //   console.error('Decryption stdout:', decResult.stdout);
  // }

  const decryptedContent = await fs.readFile(decryptedFilePath, 'utf-8');
  t.is(
    decryptedContent,
    originalContent,
    'Decrypted content should match original content'
  );

  // Clean up
  await fs.rm(tempDir, { recursive: true, force: true });
});

// Test for password required when STDIN is used for data (this is tricky as it involves interactive prompts)
// The CLI currently errors out if STDIN is data and password is not provided.
test('CLI: should error if password not provided and STDIN is data source', async (t) => {
  // This test simulates piping data to stdin. We can't directly pipe to a child process's stdin easily
  // with execFile without more complex stream management.
  // However, our CLI has a specific check: if input is '-' and no password, it tries to _stashStdIn,
  // then errors because it can't get password from stdin simultaneously.
  const { stderr, exitCode } = await runCLI(['-e', '-']); // No -p, input is stdin
  t.is(
    exitCode,
    1,
    'Should exit with code 1 when password is required for stdin data'
  );
  t.true(
    stderr.includes(
      'Error: You must provide the password if you are stream the data on STDIN.'
    ),
    'Stderr should indicate password is required for stdin data'
  );
});
