# frozen_string_literal: true

module RackJwtVerifier
  # A simple, thread-safe, in-memory cache implementation designed to mimic
  # a real cache store (like Rails.cache or Redis) but without external dependencies.
  # This is the default cache store used if the user doesn't configure one.
  class InProcessCache
    # The cache lifespan in seconds (5 minutes)
    DEFAULT_EXPIRY = 300

    def initialize
      @store = {}
      @lock = Mutex.new # Ensure thread safety for multi-threaded environments
    end

    # Reads the value for a given key. Automatically checks for expiry.
    # @param key [String] The cache key.
    # @return [Object, nil] The cached value or nil if expired or not found.
    def read(key)
      @lock.synchronize do
        entry = @store[key]
        return nil unless entry

        value, expires_at = entry
        
        # Check if the entry is expired
        return nil if Time.now.to_i >= expires_at
        
        value
      end
    end

    # Writes a value to the cache with an optional expiration time.
    # @param key [String] The cache key.
    # @param value [Object] The value to store.
    # @param options [Hash] Options, expecting :expires_in (seconds).
    # @return [Object] The stored value.
    def write(key, value, options = {})
      @lock.synchronize do
        expiry = options[:expires_in] || DEFAULT_EXPIRY
        expires_at = Time.now.to_i + expiry
        @store[key] = [value, expires_at]
        value
      end
    end

    # Deletes an entry from the cache.
    # @param key [String] The cache key.
    # @return [Object, nil] The deleted entry value or nil.
    def delete(key)
      @lock.synchronize do
        @store.delete(key)
      end
    end
  end
end
