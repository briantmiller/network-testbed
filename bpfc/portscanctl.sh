#!/usr/bin/env bash
# portscanctl.sh -- shell-only status and runtime control for portscan-guard.bpfc.
#
# Requires: Bash 4+, awk, sed, sort, and a Linux /proc filesystem.  It calls
# bpfc -r/-w against the pinned maps and does not require Python.
#
# Examples:
#   ./portscanctl.sh --bpfc ./bpfc --map-dir /sys/fs/bpf status
#   ./portscanctl.sh --bpfc ./bpfc --map-dir /sys/fs/bpf set mode block

set -uo pipefail
LC_ALL=C
export LC_ALL

if (( BASH_VERSINFO[0] < 4 )); then
  printf 'Error: %s requires Bash 4 or later.\n' "${0##*/}" >&2
  exit 2
fi

BPFC=${BPFC:-bpfc}
MAP_DIR=${MAP_DIR:-/sys/fs/bpf}

usage() {
  cat <<'USAGE'
Usage: portscanctl.sh [--bpfc PATH] [--map-dir DIR] COMMAND [ARGUMENTS]

Inspect and manage bpfc portscan-guard pinned maps. Defaults:
  --bpfc     $BPFC or bpfc
  --map-dir  $MAP_DIR or /sys/fs/bpf

Commands:
  status                         Show source state, score, recent service, and block time.
  flows [--age SECONDS]          Show recent source/protocol/destination-port contacts.
                                 Default age is the configured scan window.
  stats                          Show global counters.
  config                         Show runtime configuration.
  set threshold N                Set distinct-services-per-window threshold (1..65535).
  set duration SECONDS           Set base enforcement duration (positive integer).
  set max-duration SECONDS       Set cap for exponential enforcement duration (base..604800).
  set window SECONDS             Set scan window (positive integer).
  set log on|off                 Enable or disable static bpfc debug-log markers.
  set mode monitor|block|reset   Select monitor-only, silent-drop, or TCP-reset operation.
  block IPv4 [SECONDS]           Manually block a source; default is configured duration.
  unblock IPv4                   Clear only a source block entry.
  clear IPv4                     Clear a source's block, current suspect score, and tracking state.
USAGE
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

require_value() {
  [[ $# -ge 2 ]] || die "option $1 requires a value"
}

is_nonnegative_integer() {
  [[ $1 =~ ^[0-9]+$ ]]
}

is_positive_integer() {
  is_nonnegative_integer "$1" && (( 10#$1 > 0 ))
}

mono_seconds() {
  awk '{print int($1)}' /proc/uptime 2>/dev/null || die 'cannot read /proc/uptime'
}

boot_epoch() {
  awk '$1 == "btime" { print $2; found=1; exit } END { if (!found) exit 1 }' /proc/stat 2>/dev/null
}

fmt_ip() {
  local value=$(( $1 & 0xffffffff ))
  printf '%d.%d.%d.%d' \
    $(( (value >> 24) & 255 )) \
    $(( (value >> 16) & 255 )) \
    $(( (value >> 8) & 255 )) \
    $(( value & 255 ))
}

ipv4_key() {
  local text=$1 a b c d octet
  local IFS=.
  read -r a b c d <<<"$text"
  [[ -n ${a:-} && -n ${b:-} && -n ${c:-} && -n ${d:-} ]] || return 1
  # A fifth component remains in d with this read form; explicitly enforce four dots.
  [[ $text =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  for octet in "$a" "$b" "$c" "$d"; do
    [[ $octet =~ ^[0-9]{1,3}$ ]] && (( 10#$octet <= 255 )) || return 1
  done
  printf '%d\n' $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}

proto_name() {
  case $1 in
    6) printf 'TCP' ;;
    17) printf 'UDP' ;;
    *) printf 'IP-%s' "$1" ;;
  esac
}

fmt_age() {
  local event=$1 now=$2 age
  (( event > 0 )) || { printf '-'; return; }
  age=$(( now - event ))
  (( age >= 0 )) || age=0
  if (( age < 60 )); then
    printf '%ss' "$age"
  elif (( age < 3600 )); then
    printf '%dm%02ds' $(( age / 60 )) $(( age % 60 ))
  else
    printf '%dh%02dm' $(( age / 3600 )) $(( (age % 3600) / 60 ))
  fi
}

fmt_wall() {
  local event=$1 btime=${2:-} epoch
  [[ -n $btime ]] && (( event > 0 )) || { printf '-'; return; }
  epoch=$(( btime + event ))
  date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf '-'
}

# Print a successful bpfc invocation's stdout. On failure, retain bpfc's
# diagnostic and return nonzero so the caller can present it once.
bpfc_capture() {
  local output status
  output=$("$BPFC" -m "$MAP_DIR" "$@" 2>&1)
  status=$?
  if (( status != 0 )); then
    printf '%s\n' "$output" >&2
    return "$status"
  fi
  printf '%s\n' "$output"
}

# Bash arithmetic stores 64-bit values as signed integers. bpfc -w parses
# unsigned 64-bit keys, so format possibly-negative map keys as unsigned text.
u64_decimal() {
  printf '%u' "$1"
}

write_map() {
  local map=$1 key=$2 value=$3 unsigned_key unsigned_value
  unsigned_key=$(u64_decimal "$key")
  unsigned_value=$(u64_decimal "$value")
  bpfc_capture -w "$map" "$unsigned_key" "$unsigned_value" >/dev/null || die "bpfc map write failed: $map"
}

# bpfc prints: [0000] Key: 0x<16 hex digits> -> Value: 0x<16 hex digits>
# Load it into a Bash associative array whose name is supplied as argument 2.
load_map() {
  local map=$1 target=$2 text key_hex value_hex
  local -n destination="$target"
  destination=()
  text=$(bpfc_capture -r "$map") || die "bpfc map read failed: $map"
  while read -r key_hex value_hex; do
    [[ -n ${key_hex:-} && -n ${value_hex:-} ]] || continue
    destination[$((16#$key_hex))]=$((16#$value_hex))
  done < <(printf '%s\n' "$text" | sed -nE 's/.*Key:[[:space:]]*0x([0-9A-Fa-f]{16})[[:space:]]*->[[:space:]]*Value:[[:space:]]*0x([0-9A-Fa-f]{16}).*/\1 \2/p')
}

cfg_value() {
  local index=$1 default=$2 value=${CFG[$1]:-0}
  if (( value != 0 )); then printf '%d' "$value"; else printf '%d' "$default"; fi
}

show_config() {
  local -A CFG LIMIT
  load_map PS_CFG CFG
  local threshold duration max_duration window log mode
  threshold=$(cfg_value 0 12)
  duration=$(cfg_value 1 900)
  load_map PS_LIMIT LIMIT
  max_duration=${LIMIT[0]:-0}
  (( max_duration != 0 )) || max_duration=86400
  window=$(cfg_value 3 60)
  log=${CFG[2]:-0}
  mode=${CFG[4]:-0}
  printf 'Runtime configuration\n'
  printf '  0: threshold (distinct services/window) = %s\n' "$threshold"
  printf '  1: base enforcement duration (seconds) = %s\n' "$duration"
  printf '  5: maximum enforcement duration (seconds) = %s\n' "$max_duration"
  if (( log )); then printf '  2: debug log (0=off, 1=on) = on\n'; else printf '  2: debug log (0=off, 1=on) = off\n'; fi
  printf '  3: scan window (seconds) = %s\n' "$window"
  case $mode in
    0) printf '  4: mode (0=monitor, 1=drop, 2=reset) = monitor\n' ;;
    1) printf '  4: mode (0=monitor, 1=drop, 2=reset) = drop\n' ;;
    2) printf '  4: mode (0=monitor, 1=drop, 2=reset) = reset (TCP RST/ACK for qualifying SYNs)\n' ;;
    *) printf '  4: mode (0=monitor, 1=drop, 2=reset) = unknown (%s)\n' "$mode" ;;
  esac
}

show_stats() {
  local -A STATS
  load_map PS_STATS STATS
  printf 'Counters since map creation\n'
  printf '  new distinct source/service tuples: %s\n' "${STATS[0]:-0}"
  printf '  automatic enforcement entries issued: %s\n' "${STATS[1]:-0}"
  printf '  packets handled while enforcement was active: %s\n' "${STATS[2]:-0}"
  printf '  qualifying TCP SYNs observed: %s\n' "${STATS[3]:-0}"
  printf '  UDP packets observed: %s\n' "${STATS[4]:-0}"
}

show_status() {
  local -A SCORE LAST BLOCK BACKOFF CFG KEYS SOURCE_SCORE
  local key score_key source_key score_window score backoff last_record observed proto port until status detail age wall left
  local now btime threshold window mode window_id rows
  load_map PS_SCORE SCORE
  load_map PS_LAST LAST
  load_map PS_BLOCK BLOCK
  load_map PS_BACKOFF BACKOFF
  load_map PS_CFG CFG
  now=$(mono_seconds)
  btime=$(boot_epoch || true)
  threshold=$(cfg_value 0 12)
  window=$(cfg_value 3 60)
  mode=${CFG[4]:-0}
  window_id=$(( now / window ))
  keycount=0

  # PS_SCORE uses (fixed-window number << 32) | source IPv4 as its key. Only
  # the current window contributes to detection or the displayed score.
  for score_key in "${!SCORE[@]}"; do
    score_window=$(( score_key >> 32 ))
    (( score_window == window_id )) || continue
    source_key=$(( score_key & 0xffffffff ))
    SOURCE_SCORE[$source_key]=${SCORE[$score_key]}
    KEYS[$source_key]=1
  done
  for key in "${!LAST[@]}" "${!BLOCK[@]}" "${!BACKOFF[@]}"; do
    [[ -n ${key:-} ]] || continue
    if [[ -v BLOCK[$key] ]] && (( BLOCK[$key] == 0 )) && [[ ! -v LAST[$key] && ! -v SOURCE_SCORE[$key] ]]; then
      continue
    fi
        keycount=$(( $keycount + 1 ))
    KEYS[$key]=1
  done

  printf 'Source states (score is authoritative for the current fixed scan-time bucket)\n'
  printf '%-16s %-9s %5s %7s %-12s %-9s %-21s %10s\n' 'SOURCE' 'STATE' 'SCORE' 'LEVEL' 'LAST SERVICE' 'LAST SEEN' 'UTC (approx.)' 'ENFORCE LEFT'
  printf '%s\n' '------------------------------------------------------------------------------------------------------------'
  if [ $keycount -gt 0 ]
  then
    ((${#KEYS[@]}))
  else
    printf '(no qualifying TCP SYN or UDP observations recorded)\n'; return;
  fi

  rows=$(
    for key in "${!KEYS[@]}"; do
      score=${SOURCE_SCORE[$key]:-0}
      backoff=${BACKOFF[$key]:-0}
      last_record=${LAST[$key]:-0}
      observed=$(( last_record >> 32 ))
      proto=$(( (last_record >> 16) & 0xff ))
      port=$(( last_record & 0xffff ))
      until=${BLOCK[$key]:-0}
      if (( until > now )); then
        if (( mode == 2 )); then status=TCP-RST; else status=BLOCKED; fi
        priority=0
      elif (( score >= threshold )); then
        status=SUSPECT; priority=1
      elif (( score > 0 )); then
        status=TRACKING; priority=2
      else
        status=ALLOWED; priority=3
      fi
      if (( last_record )); then detail="$(proto_name "$proto")/$port"; else detail='-'; fi
      age=$(fmt_age "$observed" "$now")
      wall=$(fmt_wall "$observed" "$btime")
      left=$(( until > now ? until - now : 0 ))
      printf '%s\t%020d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$priority" "$score" "$(fmt_ip "$key")" "$status" "$backoff" "$detail" "$age" "$wall" "$left"
    done | sort -t $'\t' -k1,1n -k2,2nr -k3,3
  )
  while IFS=$'\t' read -r _priority _score source status backoff detail age wall left; do
    [[ -n ${source:-} ]] || continue
    if (( left )); then block_text="${left}s"; else block_text='-'; fi
    printf '%-16s %-9s %5d %7d %-12s %-9s %-21s %10s\n' "$source" "$status" "$((10#$_score))" "$backoff" "$detail" "$age" "$wall" "$block_text"
  done <<< "$rows"
}
show_flows() {
  local requested_age=${1:-} age_limit now btime seen key source proto port age rows
  local -A FLOW CFG
  load_map PS_FLOW FLOW
  load_map PS_CFG CFG
  if [[ -n $requested_age ]]; then
    age_limit=$requested_age
  else
    age_limit=$(cfg_value 3 60)
  fi
  now=$(mono_seconds)
  btime=$(boot_epoch || true)

  printf 'Recently observed qualifying service contacts (age <= %ss)\n' "$age_limit"
  printf '%-16s %-7s %8s %8s %-21s\n' 'SOURCE' 'PROTO' 'DST PORT' 'AGE' 'UTC (approx.)'
  printf '%s\n' '----------------------------------------------------------------------'

  rows=$(
    for key in "${!FLOW[@]}"; do
      seen=${FLOW[$key]}
      age=$(( now - seen )); (( age >= 0 )) || age=0
      (( age <= age_limit )) || continue
      source=$(( key >> 32 ))
      proto=$(( (key >> 16) & 0xff ))
      port=$(( key & 0xffff ))
      printf '%020d\t%s\t%s\t%s\t%s\t%s\n' "$seen" "$(fmt_ip "$source")" "$(proto_name "$proto")" "$port" "$(fmt_age "$seen" "$now")" "$(fmt_wall "$seen" "$btime")"
    done | sort -t $'\t' -k1,1nr
  )
  [[ -n $rows ]] || { printf '(none in the selected interval)\n'; return; }
  while IFS=$'\t' read -r _seen source proto port age wall; do
    [[ -n ${source:-} ]] || continue
    printf '%-16s %-7s %8d %8s %-21s\n' "$source" "$proto" "$port" "$age" "$wall"
  done <<< "$rows"
}

# Clear current operational state for a source. This is intentionally broader
# than `unblock`: it removes the active block, the current fixed-window score,
# the last-contact record, and all source-matching PS_FLOW tuple timestamps.
# `bpfc -w` updates map values rather than deleting keys; a zero PS_FLOW value
# makes a later contact eligible to be claimed as new again.
clear_source() {
  local text_ip=$1 ip now window window_id score_key key source
  local flow_count=0 score_count=0
  local -A CFG SCORE FLOW

  ip=$(ipv4_key "$text_ip") || die "invalid IPv4 address: $text_ip"
  load_map PS_CFG CFG
  window=$(cfg_value 3 60)
  now=$(mono_seconds)
  window_id=$(( now / window ))

  # Clear all retained score-bucket entries for the source, including the
  # current bucket that determines SUSPECT status.
  load_map PS_SCORE SCORE
  for key in "${!SCORE[@]}"; do
    source=$(( key & 0xffffffff ))
    if (( source == ip )); then
      write_map PS_SCORE "$key" 0
      ((score_count += 1))
    fi
  done
  # Ensure a current-bucket map entry is cleared even if it was not present in
  # the dump at the instant above.
  score_key=$(( (window_id << 32) | ip ))
  if [[ ! -v SCORE[$score_key] ]]; then
    write_map PS_SCORE "$score_key" 0
  fi

  write_map PS_BLOCK "$ip" 0
  write_map PS_BACKOFF "$ip" 0
  write_map PS_LAST "$ip" 0

  # Clear all retained tuple timestamps for this source so it no longer appears
  # in the flow view and can begin a fresh tracking interval if it returns.
  load_map PS_FLOW FLOW
  for key in "${!FLOW[@]}"; do
    source=$(( (key >> 32) & 0xffffffff ))
    if (( source == ip )); then
      write_map PS_FLOW "$key" 0
      ((flow_count += 1))
    fi
  done

  printf 'Cleared %s: enforcement, backoff level, %d score bucket(s), last-contact record, and %d flow tuple(s).\n' \
    "$text_ip" "$score_count" "$flow_count"
  printf 'Note: if the source is still sending traffic, packet processing can recreate state immediately.\n'
}

set_config() {
  local setting=$1 value_text=$2 index value
  case $setting in
    threshold)
      is_positive_integer "$value_text" || die 'threshold must be a positive integer'
      (( 10#$value_text <= 65535 )) || die 'threshold must be <= 65535'
      index=0; value=$((10#$value_text)) ;;
    duration)
      is_positive_integer "$value_text" || die 'duration must be a positive integer'
      value=$((10#$value_text))
      local -A LIMIT
      load_map PS_LIMIT LIMIT
      local max_duration=${LIMIT[0]:-0}
      (( max_duration != 0 )) || max_duration=86400
      (( value <= max_duration )) || die 'duration must not exceed max-duration'
      index=1 ;;
    max-duration|max)
      is_positive_integer "$value_text" || die 'max-duration must be a positive integer'
      value=$((10#$value_text))
      (( value <= 604800 )) || die 'max-duration must be <= 604800 seconds (7 days)'
      local -A CURRENT_CFG
      load_map PS_CFG CURRENT_CFG
      local base_duration=${CURRENT_CFG[1]:-0}
      (( base_duration != 0 )) || base_duration=900
      (( value >= base_duration )) || die 'max-duration must be >= duration'
      write_map PS_LIMIT 0 "$value"
      printf 'Set max-duration to %s.\n' "$value_text"
      return ;;
    window)
      is_positive_integer "$value_text" || die 'window must be a positive integer'
      index=3; value=$((10#$value_text)) ;;
    log)
      case ${value_text,,} in on) value=1 ;; off) value=0 ;; *) die 'log must be on or off' ;; esac
      index=2 ;;
    mode)
      case ${value_text,,} in
        monitor) value=0 ;;
        block|drop) value=1 ;;
        reset|closed|tcp-reset) value=2 ;;
        *) die 'mode must be monitor, block/drop, or reset' ;;
      esac
      index=4 ;;
    *) die "unknown setting: $setting" ;;
  esac
  write_map PS_CFG "$index" "$value"
  printf 'Set %s to %s.\n' "$setting" "$value_text"
}

while (( $# )); do
  case $1 in
    --bpfc) require_value "$@"; BPFC=$2; shift 2 ;;
    --map-dir) require_value "$@"; MAP_DIR=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) die "unknown option: $1" ;;
    *) break ;;
  esac
done

command=${1:-}
[[ -n $command ]] || { usage >&2; exit 2; }
shift

case $command in
  status)
    (( $# == 0 )) || die 'status takes no arguments'
    show_status ;;
  flows)
    age=''
    if (( $# )); then
      [[ ${1:-} == --age ]] || die 'flows accepts only --age SECONDS'
      [[ $# -eq 2 ]] || die 'flows --age requires one value'
      is_nonnegative_integer "$2" || die '--age must be a non-negative integer'
      age=$((10#$2))
    fi
    show_flows "$age" ;;
  stats)
    (( $# == 0 )) || die 'stats takes no arguments'
    show_stats ;;
  config)
    (( $# == 0 )) || die 'config takes no arguments'
    show_config ;;
  set)
    (( $# == 2 )) || die 'usage: set threshold|duration|max-duration|window|log|mode VALUE'
    set_config "$1" "$2" ;;
  block)
    (( $# == 1 || $# == 2 )) || die 'usage: block IPv4 [SECONDS]'
    ip=$(ipv4_key "$1") || die "invalid IPv4 address: $1"
    if (( $# == 2 )); then
      is_positive_integer "$2" || die 'block duration must be a positive integer'
      seconds=$((10#$2))
    else
      declare -A CFG
      load_map PS_CFG CFG
      seconds=$(cfg_value 1 900)
    fi
    write_map PS_BLOCK "$ip" "$(( $(mono_seconds) + seconds ))"
    write_map PS_BACKOFF "$ip" 0
    printf 'Blocked %s for %s seconds.\n' "$1" "$seconds" ;;
  unblock)
    (( $# == 1 )) || die 'usage: unblock IPv4'
    ip=$(ipv4_key "$1") || die "invalid IPv4 address: $1"
    write_map PS_BLOCK "$ip" 0
    write_map PS_BACKOFF "$ip" 0
    printf 'Cleared enforcement and backoff level for %s.\n' "$1" ;;
  clear)
    (( $# == 1 )) || die 'usage: clear IPv4'
    clear_source "$1" ;;
  -h|--help|help)
    usage ;;
  *)
    die "unknown command: $command" ;;
esac

