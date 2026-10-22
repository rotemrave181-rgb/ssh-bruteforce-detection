# =============================================================================
# SSH Brute-Force Detection from Linux auth logs
# Author: Rotem Rave
#
# Parses an OpenSSH auth log (/var/log/auth.log format), aggregates login
# attempts per source IP and flags four attack patterns:
#   1. BURST       - many failed logins from one IP within a short time window
#   2. ENUMERATION - many different (often non-existent) usernames tried
#   3. LOW_AND_SLOW- steady failures spread over hours (evades burst rules)
#   4. COMPROMISE  - a successful login right after a run of failures
#
# Base R only - no packages to install.
# Usage:  Rscript R/detect_bruteforce.R [path/to/auth.log]
# =============================================================================

# ---- Parameters (tune to your environment) ---------------------------------
WINDOW_MIN       <- 5     # sliding window length, minutes
BURST_THRESHOLD  <- 20    # failures inside one window => BURST
ENUM_USERS       <- 5     # distinct usernames tried => ENUMERATION
SLOW_MIN_FAILS   <- 50    # total failures for LOW_AND_SLOW
SLOW_MIN_HOURS   <- 3     # ...spread over at least this many hours
COMPROMISE_FAILS <- 10    # failures before a success => COMPROMISE
LOG_YEAR         <- 2026  # syslog lines carry no year

options(width = 140)
args     <- commandArgs(trailingOnly = TRUE)
log_path <- if (length(args) > 0) args[1] else "data/auth_sample.log"
out_dir  <- "output"
dir.create(out_dir, showWarnings = FALSE)

# ---- 1. Parse ----------------------------------------------------------------
lines <- readLines(log_path, warn = FALSE)

pattern <- paste0(
  "^(\\w{3}\\s+\\d+\\s[\\d:]{8}) \\S+ sshd\\[\\d+\\]: ",
  "(Failed password|Accepted password) for (invalid user )?(\\S+) ",
  "from ([0-9a-fA-F:.]+) port \\d+"
)
hit <- regmatches(lines, regexec(pattern, lines, perl = TRUE))
hit <- hit[lengths(hit) == 6]

events <- data.frame(
  time    = as.POSIXct(paste(LOG_YEAR, sapply(hit, `[`, 2)),
                       format = "%Y %b %d %H:%M:%S", tz = "UTC"),
  result  = ifelse(sapply(hit, `[`, 3) == "Accepted password", "success", "failure"),
  invalid = sapply(hit, `[`, 4) != "",
  user    = sapply(hit, `[`, 5),
  ip      = sapply(hit, `[`, 6),
  stringsAsFactors = FALSE
)
events <- events[order(events$time), ]
cat(sprintf("Parsed %d authentication events from %d log lines\n",
            nrow(events), length(lines)))

# ---- 2. Per-IP features ----------------------------------------------------
# Max failures inside any WINDOW_MIN-minute sliding window (two-pointer scan)
max_in_window <- function(t, window_sec) {
  if (length(t) == 0) return(0L)
  t <- sort(as.numeric(t)); best <- 0L; j <- 1L
  for (i in seq_along(t)) {
    while (t[i] - t[j] > window_sec) j <- j + 1L
    best <- max(best, i - j + 1L)
  }
  best
}

# Failures immediately preceding a successful login from the same IP
fails_before_success <- function(df) {
  run <- 0L; worst <- 0L
  for (r in df$result) {
    if (r == "failure") run <- run + 1L
    else { worst <- max(worst, run); run <- 0L }
  }
  worst
}

per_ip <- do.call(rbind, lapply(split(events, events$ip), function(d) {
  f <- d[d$result == "failure", ]
  data.frame(
    ip               = d$ip[1],
    failures         = nrow(f),
    successes        = sum(d$result == "success"),
    distinct_users   = length(unique(f$user)),
    invalid_users    = sum(f$invalid),
    first_seen       = min(d$time),
    last_seen        = max(d$time),
    active_hours     = round(as.numeric(difftime(max(d$time), min(d$time),
                                                 units = "hours")), 1),
    max_fails_window = max_in_window(f$time, WINDOW_MIN * 60),
    fails_before_ok  = fails_before_success(d),
    stringsAsFactors = FALSE
  )
}))

# ---- 3. Detection rules ----------------------------------------------------
flag <- function(cond, label) ifelse(cond, label, "")
per_ip$flags <- trimws(gsub("\\s+", " ", paste(
  flag(per_ip$max_fails_window >= BURST_THRESHOLD, "BURST"),
  flag(per_ip$distinct_users >= ENUM_USERS, "ENUMERATION"),
  flag(per_ip$failures >= SLOW_MIN_FAILS & per_ip$active_hours >= SLOW_MIN_HOURS &
         per_ip$max_fails_window < BURST_THRESHOLD, "LOW_AND_SLOW"),
  flag(per_ip$fails_before_ok >= COMPROMISE_FAILS, "COMPROMISE")
)))

per_ip$severity <- ifelse(grepl("COMPROMISE", per_ip$flags), "CRITICAL",
                   ifelse(per_ip$flags != "", "HIGH", "OK"))
per_ip <- per_ip[order(match(per_ip$severity, c("CRITICAL", "HIGH", "OK")),
                       -per_ip$failures), ]

suspicious <- per_ip[per_ip$severity != "OK", ]
write.csv(per_ip, file.path(out_dir, "ip_summary.csv"), row.names = FALSE)
write.csv(suspicious, file.path(out_dir, "suspicious_ips.csv"), row.names = FALSE)

# Ready-to-use firewall rules for the flagged IPs
writeLines(c("# Suggested block list - review before applying",
             sprintf("iptables -A INPUT -s %s -p tcp --dport 22 -j DROP", suspicious$ip)),
           file.path(out_dir, "blocklist.txt"))

# ---- 4. Report -------------------------------------------------------------
cat("\n=== Detection summary ===\n")
cat(sprintf("Source IPs seen: %d | flagged: %d (critical: %d)\n",
            nrow(per_ip), nrow(suspicious), sum(per_ip$severity == "CRITICAL")))
print(suspicious[, c("ip", "severity", "flags", "failures", "distinct_users",
                     "max_fails_window", "active_hours")], row.names = FALSE)

# ---- 5. Plots --------------------------------------------------------------
pal <- c(CRITICAL = "#C0392B", HIGH = "#E67E22", OK = "#7F8C8D")

# 5a. Failed logins per hour, stacked by flagged vs. normal source
fails <- events[events$result == "failure", ]
fails$hour  <- as.integer(format(fails$time, "%H"))
fails$group <- ifelse(fails$ip %in% suspicious$ip, "Flagged IPs", "Other IPs")
tab <- table(factor(fails$group, c("Flagged IPs", "Other IPs")),
             factor(fails$hour, 0:23))
png(file.path(out_dir, "failed_logins_per_hour.png"), 1000, 500, res = 110)
par(mar = c(4.5, 4.5, 3, 1))
barplot(tab, col = c("#C0392B", "#95A5A6"), border = NA, las = 1,
        xlab = "Hour of day (UTC)", ylab = "Failed logins",
        main = "Failed SSH logins per hour")
legend("topright", rownames(tab), fill = c("#C0392B", "#95A5A6"), bty = "n")
invisible(dev.off())

# 5b. Attack fingerprint: total failures vs. peak 5-minute burst per IP
png(file.path(out_dir, "attack_fingerprint.png"), 900, 600, res = 110)
par(mar = c(4.5, 4.5, 3, 1))
x <- pmax(per_ip$failures, 1); y <- pmax(per_ip$max_fails_window, 1)
plot(x, y, log = "xy", pch = 19, cex = 1.6, col = pal[per_ip$severity],
     xlim = c(1, max(x) * 3), ylim = c(1, max(y) * 2),
     xlab = "Total failed logins (log)",
     ylab = sprintf("Peak failures in %d-min window (log)", WINDOW_MIN),
     main = "Attack fingerprint per source IP")
abline(h = BURST_THRESHOLD, lty = 2, col = "grey50")
lab_pos <- ifelse(rank(x) %% 2 == 0, 3, 1)   # alternate above/below to avoid overlap
text(x, y, ifelse(per_ip$severity == "OK", "", per_ip$ip), pos = lab_pos, cex = 0.75)
legend("topleft", names(pal), col = pal, pch = 19, bty = "n")
invisible(dev.off())

cat(sprintf("\nOutputs written to %s/\n", out_dir))
