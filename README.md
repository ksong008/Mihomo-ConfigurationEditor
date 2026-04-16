# Mihomo Configuration Editor

A browser-based editor for creating, editing, importing, and exporting `mihomo` configuration files.

## Overview

This repository contains a static HTML/Vue frontend for editing common `mihomo` settings through a form-based UI. It is designed to let you work with configuration data directly in the browser without requiring a separate backend service.

## Features

- Browser-based editor with no local build step required for basic usage
- YAML import, preview, copy, and download workflow
- Dedicated sections for system settings, network and DNS, subscriptions, rule providers, proxy groups, rules, and TProxy
- Local persistence support with cache reset and recovery helpers
- Modular frontend structure split into `core/` and `modules/`

## Project Structure

- `mihomo.html`: application entry page
- `mihomo.styles.css`: application styles
- `mihomo.app.js`: thin bootstrap entry
- `mihomo.helpers.js`: shared helper utilities
- `core/`: app bootstrap, state, persistence, providers, import/export, and UI runtime
- `modules/`: feature modules for proxies, DNS, rules, TProxy, and YAML generation

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/ksong008/Mihomo-ConfigurationEditor.git
   cd Mihomo-ConfigurationEditor
   ```

2. Open `mihomo.html` directly in a browser, or run a simple local static server:

   ```bash
   python3 -m http.server 8000
   ```

3. Visit `http://127.0.0.1:8000/mihomo.html` if you started the local server.

## Usage

1. Open the editor in a browser.
2. Adjust settings in the relevant tabs.
3. Import an existing YAML file if needed.
4. Copy or download the generated configuration.

## Development Notes

- The app is implemented as a static frontend using HTML, CSS, and plain JavaScript modules.
- Frontend dependencies are loaded from CDN references declared in `mihomo.html`.
- Most feature logic is organized under `core/` and `modules/` to keep the entry file thin.

## Contributing

Contributions are welcome. Open an issue or submit a pull request for bugs, enhancements, or feature requests.

## License

This project is licensed under GPL-3.0. See `LICENSE` for details.
