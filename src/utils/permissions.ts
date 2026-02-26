export function isRoot(): boolean {
  return process.getuid?.() === 0;
}
