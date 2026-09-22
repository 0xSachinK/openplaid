import { expect, it } from "vitest";
import fixture from "../banks/us/mercury/fixtures/sent.synthetic.json";
import { interpretMercury } from "../banks/us/mercury/transformer.js";
import { matchPayment } from "./match";

const observation = interpretMercury(fixture.input, fixture.transactionId);
const claim = {
  payerId: "synthetic-payer-account",
  payeeId: "000000000:000000000001",
  amountMinor: "12345",
  currency: "USD",
};
it("matches all payment facts", () =>
  expect(matchPayment(observation, claim).outcome).toBe("supported"));
it.each(["payerId", "payeeId", "amountMinor", "currency"] as const)(
  "rejects mismatching %s",
  (key) =>
    expect(
      matchPayment(observation, { ...claim, [key]: key === "amountMinor" ? "999" : "different" })
        .outcome,
    ).toBe("contradicted"),
);
it.each([{ amountMinor: "0" }, { payerId: "" }, { payeeId: "" }])(
  "requires a well-formed claim %j",
  (patch) =>
    expect(matchPayment(observation, { ...claim, ...patch }).outcome).toBe("insufficient_evidence"),
);
it("preserves insufficient evidence", () =>
  expect(matchPayment({ outcome: "insufficient_evidence", reason: "missing" }, claim)).toEqual({
    outcome: "insufficient_evidence",
    reason: "missing",
  }));
