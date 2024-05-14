require 'jwt'
require 'net/http'

class Auth0Client
    Error = Struct.new(:message, :status)
    Response = Struct.new(:decoded_token, :error)

    def self.domain_url
        ENV["AUTH0_ISSUER_URL"]
    end

    def self.decode_token(token, jwks_hash)
        JWT.decode(token, nil, true, {
            algorithms: ['RS256'],
            iss: domain_url,
            verify_iss: true,
            aud: ENV["AUTH0_AUDIENCE"],
            verify_aud: true,
            jwks: { keys: jwks_hash[:keys] }
        })
    end

    def self.get_jwks
        jwks_uri = URI("#{domain_url}.well-known/jwks.json")
        Net::HTTP.get_response(jwks_uri)
    end

    def self.validade_token(token)
        jwks_response = get_jwks

        unless jwks_response.is_a? Net::HTTPSuccess
            error = Error.new(message: "Unable to verify credentials", status: :internal_server_error)
            return Response.new(nil, error)
        end

        jwks_hash  = JSON.parse(jwks_response.body).deep_symbolize_keys

        decoded_token = decode_token(token, jwks_hash)

        Response.new(decoded_token, nil)

        rescue JWT::VerificationError, JWT::DecodeError => e
            error = Error.new("Bad credentials", :unauthorized)
            Response.new(nil, error)
    end
end