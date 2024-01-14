# Password Checker

![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)

## Description

This tool checks whether passwords have been compromised in data breaches by querying the [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) using the SHA-1 hash of the passwords.

## Features

- Passwords are checked in parallel using `p-limit` for better performance.
- Progress bars are displayed using `cli-progress` to indicate the status of password checks.

## Installation

To use this tool, follow these steps:

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/sabry-awad97/password-checker.git
   ```

2. Install dependencies:

   ```bash
   cd password-checker
   bun install
   ```

3. Run the application:

   ```bash
   bun start -- check <password1> <password2> ...
   ```

## Usage

```bash
bun start -- check <password1> <password2> ...
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE) file for details.

## Acknowledgments

- The Pwned Passwords API for providing data on compromised passwords.
- cli-progress for the interactive progress bars.
- p-limit for limiting the concurrent password checks.

## Contributing

If you'd like to contribute, please fork the repository and create a new branch. Pull requests are welcome!

## Contact

For any questions or suggestions, feel free to reach out:

- Sabry Awad
- Email: <dr.sabry1997@gmailc.com>
