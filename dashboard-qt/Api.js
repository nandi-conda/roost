// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc
//
// Plain helpers for the dashboard: JSON GETs, TID -> time, relative dates.
.pragma library

// GET url as JSON; cb(json, null) on a 2xx JSON body, else cb(null, message).
function getJson(url, cb) {
    var x = new XMLHttpRequest()
    x.onreadystatechange = function () {
        if (x.readyState !== XMLHttpRequest.DONE)
            return
        var j = null
        try { j = JSON.parse(x.responseText) } catch (e) { }
        if (x.status >= 200 && x.status < 300 && j !== null)
            cb(j, null)
        else
            cb(null, (j && (j.message || j.error)) || (x.status ? "HTTP " + x.status : "network error"))
    }
    x.open("GET", url)
    x.setRequestHeader("Accept", "application/json")
    x.send()
}

var B32 = "234567abcdefghijklmnopqrstuvwxyz"

// Unix seconds in a TID (13 base32-sortable chars, top 53 bits are
// microseconds), or 0 if s isn't a TID. The first 11 chars hold those bits,
// and their value stays below 2^53, so plain doubles are exact.
function tidSecs(s) {
    if (!/^[2-7a-z]{13}$/.test(s || ""))
        return 0
    var n = 0
    for (var i = 0; i < 11; i++)
        n = n * 32 + B32.indexOf(s[i])
    return Math.floor(n / 1000000)
}

// "4m ago" for a time in ms, relative to nowMs.
function rel(ms, nowMs) {
    var d = Math.max(0, (nowMs - ms) / 1000)
    if (d < 60) return "just now"
    if (d < 3600) return Math.floor(d / 60) + "m ago"
    if (d < 86400) return Math.floor(d / 3600) + "h ago"
    if (d < 86400 * 60) return Math.floor(d / 86400) + "d ago"
    return new Date(ms).toISOString().slice(0, 10)
}

function relIso(iso, nowMs) {
    var t = Date.parse(iso)
    return isNaN(t) ? (iso || "") : rel(t, nowMs)
}
