<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\JWT;

use DateTimeImmutable;
use Exception;
use Illuminate\Support\Collection;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use ReflectionClass;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Lcobucci extends Provider implements JWT
{
    /**
     * @var \Lcobucci\JWT\Configuration
     */
    protected $configuration;

    /**
     * Create the Lcobucci provider.
     *
     * @param string $secret
     * @param string $algo
     * @param array  $keys
     *
     * @return void
     */
    public function __construct($secret, $algo, array $keys)
    {
        parent::__construct($secret, $algo, $keys);

        $key = InMemory::plainText($secret);

        $this->configuration = Configuration::forSymmetricSigner($this->getSigner(), $key);
        $this->configuration->setValidationConstraints(new SignedWith($this->getSigner(), $key));
    }

    /**
     * Signers that this provider supports.
     *
     * @var array
     */
    protected $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    /**
     * Create a JSON Web Token.
     *
     * @param array $payload
     *
     * @return string
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     */
    public function encode(array $payload)
    {
        // Remove the signature on the builder instance first.
        // $this->configuration->builder()->unsign();

        try {
            $builder = $this->configuration->builder();

            foreach ($payload as $key => $value) {
                switch ($key) {
                    case RegisteredClaims::SUBJECT:
                        $builder->relatedTo($value);
                        break;

                    case RegisteredClaims::AUDIENCE:
                        $builder->permittedFor($value);
                        break;

                    case RegisteredClaims::EXPIRATION_TIME:
                        $time = new \DateTimeImmutable();
                        $time = $time->setTimestamp($value);
                        $builder->expiresAt($time);
                        break;

                    case RegisteredClaims::ID:
                        $builder->identifiedBy($value);
                        break;

                    case RegisteredClaims::ISSUED_AT:
                        $time = new \DateTimeImmutable();
                        $time = $time->setTimestamp($value);
                        $builder->issuedAt($time);
                        break;

                    case RegisteredClaims::ISSUER:
                        $builder->issuedBy($value);
                        break;

                    case RegisteredClaims::NOT_BEFORE:
                        $time = new \DateTimeImmutable();
                        $time = $time->setTimestamp($value);
                        $builder->canOnlyBeUsedAfter($time);
                        break;

                    default:
                        $builder->withClaim($key, $value);
                        break;
                }
            }

            return $builder
                ->getToken($this->configuration->signer(), $this->configuration->signingKey())
                ->toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param string $token
     *
     * @return array
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     */
    public function decode($token)
    {
        try {
            $jwt = $this->configuration->parser()->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), $e->getCode(), $e);
        }

        if (! $this->configuration->validator()->validate($jwt, ...$this->configuration->validationConstraints())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (new Collection($jwt->claims()->all()))->map(function ($claim) {
            if ($claim instanceof DateTimeImmutable) {
                return $claim->getTimestamp();
            }
            return is_object($claim) ? $claim->getValue() : $claim;
        })->toArray();
    }

    /**
     * Get the signer instance.
     *
     * @return \Lcobucci\JWT\Signer
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     */
    protected function getSigner()
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        return new $this->signers[$this->algo];
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        $reflect = new ReflectionClass($this->configuration->signer());

        return $reflect->isSubclassOf(Rsa::class) || $reflect->isSubclassOf(Ecdsa::class);
    }

    /**
     * {@inheritdoc}
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric() ?
            InMemory::plainText($this->getPublicKey(), $this->getPassphrase()) :
            $this->getSecret();
    }

    /**
     * {@inheritdoc}
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric() ?
            InMemory::plainText($this->getPublicKey()) :
            $this->getSecret();
    }
}
