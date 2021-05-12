'use strict'

const { AssertionError } = require('assert')
const test = require('tape');
const { parse, LINE_TYPES } = require('../')
const { readFileSync } = require('fs')
const { join } = require('path');
const { EOL } = require('os');

test('should throw error on non-string args', (t) => {
  try {
    parse()
    t.fail('parser should have thrown an assertion error')
  } catch (e) {
    t.assert(e instanceof AssertionError)
    t.assert(e.toString().includes('dnsmasq parser expects a single string argument'))
    t.end()
  }
});

test('should throw error on empty string args', (t) => {
  try {
    parse('')
    t.fail('parser should have thrown an assertion error')
  } catch (e) {
    t.assert(e instanceof AssertionError)
    t.assert(e.toString().includes('dnsmasq parser expects a non-empty string argument'))
    t.end()
  }
});

test('should ignore startup log lines', (t) => {
  const filepath = join(__dirname, '../fixtures', 'pihole.startup.log')
  const logfile = readFileSync(filepath).toString()

  logfile.split(EOL).forEach((line) => {
    if (line === '') return

    const result = parse(line)

    t.equal(result, undefined)
  })

  t.end()
});

test('should ignore pi-hole self resolution', (t) => {
  const result = parse('May 10 10:56:22 dnsmasq[414]: 27 127.0.0.1/52805 /etc/pihole/local.list pi.hole is 192.168.1.4')

  t.equal(result, undefined)
  t.end()
})

test('should parse "query[A]" logs', (t) => {
  const result = parse('May  9 22:04:25 dnsmasq[412]: 2 172.17.0.1/37431 query[A] redhat.com from 172.17.0.1')

  t.deepEqual(result, {
    ts: '2001-05-09T21:04:25.000Z',
    type: LINE_TYPES.QUERY,
    data: {
      id: '2',
      client_address: '172.17.0.1',
      query_port: '37431',
      domain: 'redhat.com',
      query_type: 'A'
    }
  })
  t.end()
})

test('should parse "query[type=65]" logs', (t) => {
  const result = parse('May  9 22:04:27 dnsmasq[412]: 20 192.168.1.3/64007 query[type=65] tools.l.google.com from 192.168.1.3')
  t.deepEqual(result, {
    ts: '2001-05-09T21:04:27.000Z',
    type: LINE_TYPES.QUERY,
    data: {
      id: '20',
      client_address: '192.168.1.3',
      query_port: '64007',
      domain: 'tools.l.google.com',
      query_type: 'type=65'
    }
  })
  t.end()
})

test('should parse "gravity blocked" logs', (t) => {
  const result = parse('May  9 22:04:26 dnsmasq[412]: 14 172.17.0.1/33242 gravity blocked vortex.data.microsoft.com is ::')

  t.deepEqual(result, {
    ts: '2001-05-09T21:04:26.000Z',
    type: LINE_TYPES.GRAVITY,
    data: {
      id: '14',
      client_address: '172.17.0.1',
      query_port: '33242',
      domain: 'vortex.data.microsoft.com',
    }
  })
  t.end()
})

test('should handle "cached" logs', (t) => {
  const result = parse('May  9 22:04:27 dnsmasq[412]: 21 192.168.1.3/63101 cached tools.l.google.com is 74.125.193.139')

  t.deepEqual(result, {
    ts: '2001-05-09T21:04:27.000Z',
    type: LINE_TYPES.CACHED,
    data: {
      id: '21',
      client_address: '192.168.1.3',
      query_port: '63101',
      domain: 'tools.l.google.com',
      address: '74.125.193.139'
    }
  })
  t.end()
})

test('should parse "forwarded" logs', (t) => {
  const result = parse('May  9 22:04:26 dnsmasq[412]: 12 172.17.0.1/42353 forwarded openshiftapps.com to 1.0.0.1')

  t.deepEqual(result, {
    ts: '2001-05-09T21:04:26.000Z',
    type: LINE_TYPES.FORWARDED,
    data: {
      id: '12',
      client_address: '172.17.0.1',
      query_port: '42353',
      domain: 'openshiftapps.com',
      nameserver: '1.0.0.1'
    }
  })
  t.end()
})

test('should parse "reply" logs', (t) => {
  const result = parse('May  9 22:04:27 dnsmasq[412]: 18 172.17.0.1/59098 reply tools.l.google.com is 2a00:1450:400b:c03::65')

  t.deepEqual(result, {
    ts: '2001-05-09T21:04:27.000Z',
    type: LINE_TYPES.REPLY,
    data: {
      id: '18',
      client_address: '172.17.0.1',
      query_port: '59098',
      domain: 'tools.l.google.com',
      address: '2a00:1450:400b:c03::65'
    }
  })
  t.end()
})

test('should parse "config" logs', (t) => {
  const result = parse('May  9 21:42:43 dnsmasq[418]: 34449 192.168.1.3/54472 config use-application-dns.net is NXDOMAIN')

  t.deepEqual(result, {
    ts: '2001-05-09T20:42:43.000Z',
    type: LINE_TYPES.CONFIG,
    data: {
      id: '34449',
      client_address: '192.168.1.3',
      query_port: '54472',
      domain: 'use-application-dns.net',
      address: 'NXDOMAIN'
    }
  })
  t.end()
})

test('should throw an error for an unknown log line type', (t) => {
  const logstr = 'May  9 21:42:43 dnsmasq[418]: 34449 192.168.1.3/54472 foobar use-application-dns.net is NXDOMAIN'
  try {
    parse(logstr)
    t.fail()
  } catch (e) {
    t.assert(e.toString().match(/Unknown log type "foobar"/))
    t.end()
  }
})


test('should parse real log lines with CNAME and NODATA-IPv6', (t) => {
  const filepath = join(__dirname, '../fixtures', 'pihole.log')
  const logfile = readFileSync(filepath).toString()

  logfile.split(EOL).forEach((line) => {
    if (line === '') return

    const result = parse(line)

    if (line.includes('/etc/pihole/local.list')) {
      t.equal(result, undefined)
    } else {
      t.assert(typeof result === 'object')
    }
  })

  t.end()
});
