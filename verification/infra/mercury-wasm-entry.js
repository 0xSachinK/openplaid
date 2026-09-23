// Compiled into the guest with the adapter. The host enforces all resource limits.
const input = new Uint8Array(1048576);
let used = 0;
while (used < input.length) {
  const count = Javy.IO.readSync(0, input.subarray(used));
  if (!count) break;
  used += count;
}
const request = JSON.parse(new TextDecoder().decode(input.subarray(0, used)));
const result = OpenPlaidMercury.interpretMercury(request.evidence, request.transactionId);
Javy.IO.writeSync(1, new TextEncoder().encode(JSON.stringify(result)));
