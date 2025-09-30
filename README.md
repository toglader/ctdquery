# CTDQuery 

`ctdquery` is a simple CLI tool to authenticate against a CTD API, fetch sites and assets, and pretty print results.

## Requirements

- Python **3.8** or newer  
- `pip` package manager

## Installation

Clone or copy the files to your machine. Make sure you have Python 3.8+ installed.

Install dependencies:

```bash
pip install -r requirements.txt
```

or on Windows:

```powershell
py -m pip install -r requirements.txt
```

```MacOS and brew
python3 -m venv venv
source venv/bin/activate
pip install requests
pip install pip_system_certs
deactivate
```

## Usage

Basic usage:

```bash
./ctdquery <host> [options]
```

```MacOS and brew
source venv/bin/activate
./ctdquery <host> [options]
deactivate
```


### Examples

- **Login and print token (will be saved to `~/.ctdquery/token`):**
  ```bash
  ./ctdquery api.example.com
  ```

- **List all sites (pretty print):**
  ```bash
  ./ctdquery api.example.com --sites --pretty
  ```

- **List all assets (pretty print):**
  ```bash
  ./ctdquery api.example.com --assets --pretty
  ```

- **List assets for a specific site:**
  ```bash
  ./ctdquery api.example.com --assets --site 5 --pretty
  ```

- **Provide an existing token manually:**
  ```bash
  ./ctdquery api.example.com --token "eyJhbGciOi..."
  ```

### Options

- `--token` : Provide an existing token.  
- `--assets` : Fetch and print assets.  
- `--sites` : Fetch and print sites.  
- `--site <id>` : Limit assets to a specific site ID.  
- `--pretty` : Pretty print the output in a table.  

### Token storage

The tool stores the token in:
```
~/.ctdquery/token
```

If you don’t provide `--token`, it will try to reuse the saved token.  
If no saved token exists, it will ask for username and password.

---

## Development

Dependencies are managed in `requirements.txt`.

To install in development mode:

```bash
pip install -r requirements.txt
```

Run the program:

```bash
./ctdquery <host> --assets --pretty
```

Contributions, pull requests, and suggestions are welcome.

## License

This project is licensed under the GNU General Public License v3.0

---
© 2025 Tony Glader
