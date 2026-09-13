# frozen_string_literal: true

module RackJwtVerifier
  # A simple, thread-safe, in-memory cache implementation designed to mimic
  # a real cache store (like Rails.cache or Redis) but without external dependencies.
  # This is the default cache store used if the user doesn't configure one.
  class InProcessCache
    # The cache lifespan in seconds (5 minutes)
    DEFAULT_EXPIRY = 300

    # Expiry is measured on the monotonic clock, so a wall-clock jump (NTP
    # correction, DST) cannot extend or cut short an entry's life.
    MONOTONIC_CLOCK = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }

    # Expired entries are swept whenever the store grows past this many
    # entries, and the threshold then doubles from whatever survived. Amortised
    # O(1) per write, so a jti-per-request workload cannot grow the store
    # without bound while a single-key workload never pays for a sweep.
    SWEEP_THRESHOLD = 1024

    # @param clock [#call] Returns the current time in seconds; injectable for tests.
    def initialize(clock: MONOTONIC_CLOCK)
      @store = {}
      @lock = Mutex.new # Ensure thread safety for multi-threaded environments
      @clock = clock
      @sweep_at = SWEEP_THRESHOLD
    end

    # Reads the value for a given key. Automatically checks for expiry.
    # @param key [String] The cache key.
    # @return [Object, nil] The cached value or nil if expired or not found.
    def read(key)
      @lock.synchronize { live_value(key) }
    end

    # Writes a value to the cache with an optional expiration time.
    # @param key [String] The cache key.
    # @param value [Object] The value to store.
    # @param options [Hash] :expires_in (seconds); :unless_exist (true to keep
    #   an existing live entry, as ActiveSupport stores do).
    # @return [Object, false] The stored value, or false when :unless_exist
    #   was given and a live entry already existed.
    def write(key, value, options = {})
      @lock.synchronize do
        return false if options[:unless_exist] && !live_value(key).nil?

        expiry = options[:expires_in] || DEFAULT_EXPIRY
        @store[key] = [value, @clock.call + expiry]
        sweep_if_needed
        value
      end
    end

    # Deletes an entry from the cache.
    # @param key [String] The cache key.
    # @return [Object, nil] The deleted entry value or nil.
    def delete(key)
      @lock.synchronize do
        entry = @store.delete(key)
        entry&.first
      end
    end

    # Removes every entry.
    def clear
      @lock.synchronize do
        @store.clear
        @sweep_at = SWEEP_THRESHOLD
      end
      nil
    end

    # Number of entries held, expired ones included until the next sweep.
    def size
      @lock.synchronize { @store.size }
    end

    private

    # Caller holds the lock.
    def live_value(key)
      entry = @store[key]
      return nil unless entry

      value, expires_at = entry
      return nil if @clock.call >= expires_at

      value
    end

    # Caller holds the lock.
    def sweep_if_needed
      return if @store.size <= @sweep_at

      now = @clock.call
      @store.delete_if { |_, (_, expires_at)| now >= expires_at }
      @sweep_at = [@store.size * 2, SWEEP_THRESHOLD].max
    end
  end
end
