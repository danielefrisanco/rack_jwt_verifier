# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RackJwtVerifier::InProcessCache do
  # A controllable clock: expiry is measured on the monotonic clock, which
  # Timecop cannot move, so the cache takes its clock by injection.
  let(:now) { [0.0] }
  subject(:cache) { described_class.new(clock: -> { now[0] }) }

  def advance(seconds)
    now[0] += seconds
  end

  let(:key) { 'some:key' }
  let(:value) { 'some value' }

  describe '#read' do
    it 'returns nil for a key that was never written' do
      expect(cache.read(key)).to be_nil
    end

    it 'returns the value that was written' do
      cache.write(key, value)
      expect(cache.read(key)).to eq(value)
    end
  end

  describe '#write' do
    it 'returns the value written' do
      expect(cache.write(key, value)).to eq(value)
    end

    it 'overwrites an existing entry' do
      cache.write(key, 'old')
      cache.write(key, 'new')
      expect(cache.read(key)).to eq('new')
    end

    it 'keeps entries for different keys apart' do
      cache.write('a', 1)
      cache.write('b', 2)
      expect([cache.read('a'), cache.read('b')]).to eq([1, 2])
    end
  end

  describe 'expiry' do
    it 'serves the entry right up to the default TTL' do
      cache.write(key, value)
      advance(described_class::DEFAULT_EXPIRY - 1)
      expect(cache.read(key)).to eq(value)
    end

    it 'expires the entry once the default TTL has elapsed' do
      cache.write(key, value)
      advance(described_class::DEFAULT_EXPIRY)
      expect(cache.read(key)).to be_nil
    end

    it 'honours an explicit expires_in' do
      cache.write(key, value, expires_in: 10)
      advance(9)
      expect(cache.read(key)).to eq(value)
      advance(1)
      expect(cache.read(key)).to be_nil
    end

    it 'lets a rewrite extend the lifetime' do
      cache.write(key, value, expires_in: 10)
      advance(8)
      cache.write(key, value, expires_in: 10)
      advance(7)
      expect(cache.read(key)).to eq(value)
    end

    it 'uses the monotonic clock by default' do
      real = described_class.new
      real.write(key, value, expires_in: 60)
      Timecop.travel(Time.now + 3600) { expect(real.read(key)).to eq(value) }
    end
  end

  describe '#delete' do
    it 'removes the entry and returns its value' do
      cache.write(key, value)
      expect(cache.delete(key)).to eq(value)
      expect(cache.read(key)).to be_nil
    end

    it 'returns nil for a key that is not present' do
      expect(cache.delete('missing')).to be_nil
    end
  end

  describe 'thread safety' do
    it 'survives concurrent reads, writes and deletes without corrupting entries' do
      threads = 8.times.map do |t|
        Thread.new do
          100.times do |i|
            cache.write("shared", i)
            cache.write("own:#{t}", i)
            cache.read("shared")
            cache.delete("shared") if i % 10 == 0
          end
        end
      end
      expect { threads.each(&:join) }.not_to raise_error

      8.times { |t| expect(cache.read("own:#{t}")).to eq(99) }
    end
  end
end
