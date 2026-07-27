# Password Strength Checker

A lightweight, browser-based password strength checker that gives immediate, practical feedback without sending the entered password anywhere.

## Features

- Live strength rating: Weak, Fair, Good, or Strong
- Estimated entropy and illustrative crack-time estimate
- A checklist for length, character variety, common sequences, and repeated patterns
- Personalized suggestions for improving a password
- Detection of a small set of common passwords and keyboard patterns
- Show or hide password control
- Responsive light and dark theme support
- Password best-practice tips, including passphrases, unique passwords, and two-factor authentication

## Run Locally

No installation or build step is required.

1. Clone or download this repository.
2. Open `index.html` in a modern web browser.

Alternatively, serve the directory with any static file server:

```powershell
python -m http.server 8000
```

Then visit `http://localhost:8000`.

## How It Works

The checker evaluates several password properties:

- At least 12 characters
- Lowercase and uppercase letters
- Numbers and special characters
- Absence of common sequences such as `123`, `abc`, and `qwerty`
- Absence of repeated character or pattern runs such as `aaa` or `abcabcabc`

It estimates entropy from the password length and detected character pool. The strength label and crack-time display are intended as helpful guidance, not as a guarantee that a password is secure.

## Privacy

All analysis runs locally in the browser. This project has no backend, analytics, or network requests, and it does not store or transmit passwords.

## Project Structure

|-- index.html    # Application markup
|-- styles.css    # Responsive styling and themes
|-- app.js        # Password analysis and UI updates
`-- README.md

## Technology

Built with plain HTML, CSS, and JavaScript. No external dependencies are required.

## Security Note

Do not enter a password that is actively used for a sensitive account into tools you do not trust. For important accounts, use a password manager to generate a unique password and enable two-factor authentication where available.
