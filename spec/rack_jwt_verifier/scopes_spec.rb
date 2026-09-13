# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RackJwtVerifier::Scopes do
  describe '.from' do
    it 'reads a scopes array (what jwt_auth_client emits)' do
      expect(described_class.from('scopes' => %w[read:a write:b])).to eq(%w[read:a write:b])
    end

    it 'reads a space-delimited scope string (OAuth 2 convention)' do
      expect(described_class.from('scope' => 'read:a  write:b')).to eq(%w[read:a write:b])
    end

    it 'prefers scopes over scope when both are present' do
      expect(described_class.from('scopes' => ['a'], 'scope' => 'b')).to eq(['a'])
    end

    it 'accepts symbol keys' do
      expect(described_class.from(scopes: ['a'])).to eq(['a'])
    end

    it 'returns an empty list for a missing, nil, malformed or empty claim' do
      expect(described_class.from({})).to eq([])
      expect(described_class.from('scopes' => nil)).to eq([])
      expect(described_class.from('scopes' => 42)).to eq([])
      expect(described_class.from('scopes' => ['', nil])).to eq([])
      expect(described_class.from(nil)).to eq([])
    end
  end

  describe '.missing' do
    it 'lists the required scopes the payload lacks' do
      expect(described_class.missing({ 'scopes' => ['a'] }, %w[a b])).to eq(['b'])
    end

    it 'accepts a single scope' do
      expect(described_class.missing({ 'scopes' => ['a'] }, 'a')).to eq([])
    end
  end

  describe '.include?' do
    it 'is true only when every scope is granted' do
      payload = { 'scopes' => %w[a b] }
      expect(described_class.include?(payload, 'a')).to be(true)
      expect(described_class.include?(payload, 'a', 'b')).to be(true)
      expect(described_class.include?(payload, %w[a c])).to be(false)
    end
  end
end
