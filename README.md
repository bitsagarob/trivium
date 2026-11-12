# Trivium

2-of-3 bitcoin multisig.
Three keys.
Two buttons.
Zero words.

Multi-sig is the best way to secure your bitcoin, but self-custody is already hard & multi-sig is even harder. We need to keep things super easy, super minimal. This is an experiment into how minimal multi-sig could be.

- Setup: 3 buttons to add 3 public keys.
- 1 ↓ button to receive, 1 ↑ button to send
- No words anywhere
- Browser & QR based
- Talks directly to BTC core for all cryptography
- Less than 200 lines of code!
- The url is the wallet, nothing is stored anywhere
- Open source

This is not intended as a secure wallet, it's an experiment into what's possible when you take simplification to the extreme. At this stage its just a gimmick, but I honestly love the obnoxious simplicity.

To be honest, having just 1 2 3 on the screen would be confusing to most and perhaps not simple at all because of the lack of guidance. But that guidance can come from elsewhere, because there's so little functionality there's also very little to explain.

Just have 3 bitcoin keys (like a Cardsigner with 3 cards), show each public key as QR to load it into Trivium. After uploading 3 it'll show you the output descriptor. Also hold anywhere on the screen for about a second to show the descriptor QR again, tap again to close it (works only on the home screen, after all three keys are in).

Then ↓ button to receive & show QR btc address
Then ↑ button to scan a btc address QR to send.

Literally can not be simpler.

A wallet is just a URL, public keys get added to the URL as you add them, so you can simply bookmark to save.

Supports distributed setups: adding keys from different locations since after you added your key you can just share the url already, which has your public key.

Again, this is just a gimmick at this stage, but it might actually make some sense for educational purposes.
