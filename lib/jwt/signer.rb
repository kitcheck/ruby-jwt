# frozen_string_literal: true
#
module JWT
  class Signer
    ToSign = Struct.new(:algorithm, :msg, :key)

    def initialize(key, algorithm = 'HS256')
      @key = key
      @algo, @code = Algos.find(algorithm)
    end

    def algorithm
      @code
    end

    def sign(msg)
      @algo.sign ToSign.new(@code, msg, @key)
    end
  end
end
