# frozen_string_literal: true

require 'jwt/version'
require 'jwt/base64'
require 'jwt/json'
require 'jwt/decode'
require 'jwt/configuration'
require 'jwt/encode'
require 'jwt/error'
require 'jwt/jwk'
require 'jwt/signer'

# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# https://tools.ietf.org/html/rfc7519
module JWT
  extend ::JWT::Configuration

  def self.encode(payload:, header_fields: {}, signer: nil)
    Encode.new(
      payload: payload,
      headers: header_fields,
      signer: signer
    ).segments
  end

  def self.decode(jwt, key = nil, verify = true, options = {}, &keyfinder)
    Decode.new(
      jwt,
      key,
      verify,
      configuration.decode.to_h.merge(options),
      &keyfinder
    ).decode_segments
  end
end
