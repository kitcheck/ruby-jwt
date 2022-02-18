# frozen_string_literal: true

require_relative './algos'
require_relative './claims_validator'

# JWT::Encode module
module JWT
  # Encoding logic for JWT
  class Encode
    ALG_NONE = 'none'
    ALG_KEY  = 'alg'
    KID = 'kid'

    def initialize(options)
      @payload = options[:payload]
      @signer = options[:signer]
      @headers = options[:headers].transform_keys(&:to_s)
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
      if @payload.is_a?(Hash)
        ClaimsValidator.new(@payload).validate!
      end

      encode(@payload)
    end

    def encode_signature
      return '' if @signer.nil? || @signer.algorithm == ALG_NONE

      ::Base64.urlsafe_encode64(
        @signer.sign(encoded_header_and_payload),
        padding: false
      )
    end

    def encode(data)
      ::JWT::Base64.url_encode(JWT::JSON.generate(data))
    end

    def combine(*parts)
      parts.join('.')
    end
  end
end
