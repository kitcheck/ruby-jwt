# frozen_string_literal: true

require_relative './algos'
require_relative './claims_validator'

# JWT::Encode module
module JWT
  # Encoding logic for JWT
  class Encode
    ALG_NONE = 'none'.freeze
    ALG_KEY  = 'alg'.freeze
    KID = 'kid'.freeze

    def initialize(options)
      @payload = options[:payload]
      @signer = options[:signer]
      @headers = options[:headers].each_with_object({}) do |(key, value), headers|
        headers[key.to_s] = value
      end
    end

    def segments
      @segments ||= combine(encoded_header_and_payload, encoded_signature)
    end

    private

    def algorithm
      @algorithm ||= @signer&.algorithm || 'none'
    end

    def encoded_header
      @encoded_header ||= encode_header
    end

    def encoded_payload
      @encoded_payload ||= encode_payload
    end

    def encoded_signature
      @encoded_signature ||= encode_signature
    end

    def encoded_header_and_payload
      @encoded_header_and_payload ||= combine(encoded_header, encoded_payload)
    end

    def encode_header
      @headers[ALG_KEY] = algorithm
      if !@signer.nil? && @signer.respond_to?(:kid) && !@signer.kid.nil?
        @headers[KID] = @signer.kid
      end
      encode(@headers)
    end

    def encode_payload
      if @payload && @payload.is_a?(Hash)
        ClaimsValidator.new(@payload).validate!
      end

      encode(@payload)
    end

    def encode_signature
      return '' if @signer.nil? || @signer.algorithm == ALG_NONE

      Base64.urlsafe_encode64(
        @signer.sign(encoded_header_and_payload),
        padding: false
      )
    end

    def encode(data)
      Base64.urlsafe_encode64(JWT::JSON.generate(data), padding: false)
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
