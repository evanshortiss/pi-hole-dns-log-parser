# Pi-hole DNS Log Parser

Parses Pi-hole dnsmasq log lines into JSON.

For example, this string:

```
May  9 22:04:25 dnsmasq[412]: 2 172.17.0.1/37431 query[A] redhat.com from 172.17.0.1
```

Is parsed to this JSON:

```js
{
  ts: '2001-05-09T21:04:25.000Z',
  type: 'query',
  data: {
    id: '2',
    client_address: '172.17.0.1',
    domain: 'redhat.com',
    query_port: '37431',
    query_type: 'A'
  }
}
```

## Usage

```js
'use strict'

const { parse, LINE_TYPES } = require('pi-hole-dns-log-parser')

// A log line from the pi-hole logs
const log = 'May  9 22:22:22 dnsmasq[412]: 12 172.17.0.1/42353 forwarded redhat.com to 1.1.1.1'

try {
  const result = parse(log)

  if (LINE_TYPES.FORWARDED === result.type) {
    // Pretty print the parsed log JSON if it's a "forwarded" type
    console.log(JSON.stringify(result, null, 2))
  }
} catch (e) {
  // Malformed/unrecognised line types will throw an error
  console.error('error occurred when parsing log', e)
}

// Result that is printed:
//
// {
//   ts: '2001-05-09T21:22:22.000Z',
//   type: 'forwarded',
//   data: {
//     id: '12',
//     client_address: '172.17.0.1',
//     query_port: '42353',
//     domain: 'redhat.com',
//     nameserver: '1.1.1.1'
//   }
// }
```



## API

* `parse(line: string)` - Function that parses a given line from the Pi-hole logs.
* `LINE_TYPES` - Object containing the supported log line formats/types, e.g `LINE_TYPES.FORWARDED`.
