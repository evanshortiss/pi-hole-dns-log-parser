'use strict'

const assert = require('assert')

/**
 * @typedef {Object} PiholeLogTypes
 * @property {String} QUERY
 * @property {String} FORWARDED
 * @property {String} GRAVITY
 * @property {String} CACHED
 * @property {String} REPLY
 * @property {String} CONFIG
 */

/**
 * @typedef {Object} PiholeLogJsonData
 * @property {String} id - Numeric ID of this DNS query
 * @property {String} client_address - The address of the client making the query
 * @property {String} query_port - The port of the outgoing DNS query to an upstream server
 * @property {String|undefined} query_type - The port of the outgoing DNS query to an upstream server
 * @property {String|undefined} domain - Domain name being queried
 * @property {String|undefined} address - The resolved address for the query
 * @property {String|undefined} nameserver - Nameserver that the query is forwared to
 */

/**
 * @typedef {Object} PiholeLogJson
 * @property {String} ts - ISO String timestamp for the log line
 * @property {String} type - The type, i.e LINE_TYPE, of the parsed line
 * @property {PiholeLogJsonData} data - Components of the particular log
 */


/**
 * @type {PiholeLogTypes}
 */
const LINE_TYPES = exports.LINE_TYPES = {
  QUERY: 'query',
  FORWARDED: 'forwarded',
  GRAVITY: 'gravity',
  CACHED: 'cached',
  REPLY: 'reply',
  CONFIG: 'config'
}

/**
 * Parses a given line from the dnsmasq logs.
 *
 * Log lines have a few formats:
 *
 * May  9 22:04:27 dnsmasq[412]: 19 172.17.0.1/38348 query[A] tools.google.com from 172.17.0.
 * May  9 22:04:27 dnsmasq[412]: 19 172.17.0.1/38348 forwarded tools.google.com to 1.0.0.
 * May  9 22:04:27 dnsmasq[412]: 18 172.17.0.1/59098 reply tools.google.com is <CNAME>
 * May  9 22:04:27 dnsmasq[412]: 18 172.17.0.1/59098 reply tools.l.google.com is 2a00:1450:400b:c03::65
 * May  9 22:04:27 dnsmasq[412]: 19 172.17.0.1/38348 reply tools.l.google.com is 74.125.193.138
 * May  9 22:04:27 dnsmasq[412]: 20 192.168.1.3/64007 forwarded tools.l.google.com to 1.0.0.1
 * May  9 22:04:27 dnsmasq[412]: 21 192.168.1.3/63101 query[A] tools.l.google.com from 192.168.1.3
 * May  9 22:04:27 dnsmasq[412]: 21 192.168.1.3/63101 cached tools.l.google.com is 74.125.193.139
 * May  9 22:25:32 dnsmasq[412]: 475 192.168.1.3/62132 query[A] vortex.data.microsoft.com from 192.168.1.3
 * May  9 22:25:32 dnsmasq[412]: 475 192.168.1.3/62132 gravity blocked vortex.data.microsoft.com is 0.0.0.0
 * May  9 22:25:32 dnsmasq[412]: 476 192.168.1.3/59139 query[AAAA] vortex.data.microsoft.com from 192.168.1.3
 * May  9 22:25:32 dnsmasq[412]: 476 192.168.1.3/59139 gravity blocked vortex.data.microsoft.com is ::
 * May  9 22:26:42 dnsmasq[412]: 513 127.0.0.1/48367 query[A] notarealdomain-really.com from 127.0.0.1
 * May  9 22:26:42 dnsmasq[412]: 513 127.0.0.1/48367 forwarded notarealdomain-really.com to 1.0.0.1
 * May  9 22:26:42 dnsmasq[412]: 513 127.0.0.1/48367 reply notarealdomain-really.com is NXDOMAIN
 * May 10 10:56:22 dnsmasq[414]: 27 127.0.0.1/52805 /etc/pihole/local.list pi.hole is 192.168.1.4
 *
 * @param {String} line
 * @returns {PiholeLogJson}
 */
exports.parse = (line) => {
  assert(
    typeof line === 'string',
    'dnsmasq parser expects a single string argument'
  )

  assert(
    line.length !== 0,
    'dnsmasq parser expects a non-empty string argument'
  )

  if (line.includes('/etc/pihole/local.list')) {
    return
  }

  // Primary log parts, i.e the date and the log contents
  const parts = line.split('dnsmasq')

  // Should probably improve safety of this date "parsing"
  const ts = new Date(parts[0]).toISOString()

  // These are the log segments, i.e PID, query ID, client IP/port, etc.
  const logstr = parts[1].split(': ')[1]

  const parsedLog = parseLogString(logstr)

  if (parsedLog) {
    return {
      ts,
      ...parsedLog
    }
  }
}

/**
 * Parses the contents of the log portion of a line, e.g:
 * "20 192.168.1.3/64007 forwarded tools.l.google.com to 1.0.0.1"
 *
 * This function can return an object with the parsed result, or undefined
 * when the given line is considered a generic pi-hole information log.
 *
 * An error is thrown if the log is deemed to be DNS related, but is not of a
 * known type.
 *
 * @param {String} logstr
 * @returns {object|undefined}
 */
function parseLogString (logstr) {
  const segments = logstr.split(' ')

  const id = parseInt(segments[0])

  if (isNaN(id)) {
    // This was a not a query log line, so it's not of interest. It might be
    // a startup line similar to:
    //
    // May  9 22:04:22 dnsmasq[328]: started, version pi-hole-2.85
    return null
  } else {
    let type = segments[2]
    const data = {
      id: segments[0],
      client_address: segments[1].split('/')[0],
      query_port: segments[1].split('/')[1],
      domain: segments[3]
    }

    if (type === LINE_TYPES.GRAVITY) {
      // Gravity logs "gravity blocked", so indexes are shifted due to the
      // extra space versus the likes of "forwarded" or "query"
      data.domain = segments[4]
    } else if (type.startsWith(LINE_TYPES.QUERY)) {
      // Capture the query type, e.g A or AAAA
      data.query_type = type.match(/\[(.*?)\]/)[1]
      // Remove the query type, e.g translate "query[A]" to "query"
      type = LINE_TYPES.QUERY
    } else if (type === LINE_TYPES.FORWARDED) {
      // Forwarded queries specify a nameserver
      data.nameserver = segments[5]
    } else if (type === LINE_TYPES.CONFIG) {
      // Config queries have hardcoded return values, e.g to override specific behaviour or set static hostnames
      // https://discourse.pi-hole.net/t/support-for-returning-nxdomain-for-use-application-dns-net-to-disable-firefox-doh/23243
      data.address = segments[5]
    } else if (type === LINE_TYPES.REPLY || type === LINE_TYPES.CACHED) {
      // Capture the query result
      data.address = segments[5]
    } else {
      throw new Error(`Unknown log type "${type}". Log line is: "${logstr}"`)
    }

    return {
      type,
      data
    }
  }
}
