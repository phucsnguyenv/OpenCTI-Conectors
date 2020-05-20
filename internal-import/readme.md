# internal-import OpenCTI connector
This is an internal importer that read data from `.csv` or `.txt` files. 

## Configuration
- Copy the folder `./src/data` to another place.
```
├── archive
└── files
    └── sample.csv
```
- mount the folder to container `/opt/opencti-connector-internal-import`.
- create `csv` file contains data as sample file in `./data/files/sample.csv` and copy it to the `files` folder that just been created. (keeps the `sample.csv` file)

## Scope
- `ipv4-addr`
- `file-md5`
- `file-sha1`
- `file-sha256`
- `domain-name`
- `url`

## Datafile format
```
"value1","type"
...
_report,"description"
```
- first line contains data
    + `value1` is the data.
    + `type` is the type.
    + __Type accept__:
        + `ip` for IPv4
        + `domain` for domain name
        + `md5`, `sha1`, `sha256` for file hashes
        +  `url` for link
    + You can add as many lines as you want.
- last line will be the report
    + `_report` requirement.
    + `description` is the description of report.

_Each piece of data should be arrounded by __*double-quote*__ `"`._