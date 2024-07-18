# JS Link Finder

A tool for actively scanning JavaScript files for links and endpoints.

## Installation

1. Install the required packages:
    ```
    pip install -r requirements.txt
    ```

2. Run the tool:
    ```
    python js_link_finder.py
    ```

## Usage

Usage: python js_link_finder.py -u <URL> -o <output_file> [options]

Options:
-u, --url URL of the website to scan
-o, --output Output file to save results
-e, --exclude Comma-separated list of files to exclude (default: jquery,google-analytics)

