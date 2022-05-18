<?php

namespace Conduction\DigidBundle\Service;

use Conduction\CommonGroundBundle\Service\CommonGroundService;
use Conduction\CommonGroundBundle\Service\FileService;
use Conduction\SamlBundle\Security\User\AuthenticationUser;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Csrf\CsrfTokenManager;

class DigidJwtService
{
    /**
     * @var ParameterBagInterface A parameterbag for the application
     */
    private ParameterBagInterface $parameterBag;

    /**
     * @var CommonGroundService The commonground service used to access the user component
     * @TODO: Remove the User Component dependency
     */
    private CommonGroundService $commonGroundService;

    /**
     * @var CsrfTokenManager
     */
    private CsrfTokenManager $csrfTokenManager;

    /**
     * @var CacheInterface
     */
    private CacheInterface $cache;

    /**
     * The class constructor
     *
     * @param   ParameterBagInterface   $parameterBag   The parameterBag to use
     */
    public function __construct(ParameterBagInterface $parameterBag, CommonGroundService $commonGroundService)
    {
        $this->commonGroundService = $commonGroundService;
        $this->parameterBag = $parameterBag;
        $this->csrfTokenManager = new CsrfTokenManager();
    }

    /**
     * Returns the array for the user based on the authenticationUser
     * @param   AuthenticationUser  $user   The user to get data for
     * @return  array                       The array representation of the user
     */
    private function getUserArray(AuthenticationUser $user): array
    {
        return [
            'id'            => $user->getUserIdentifier(),
            'name'          => $user->getName(),
            'givenName'     => $user->getFirstName(),
            'familyName'    => $user->getLastName(),
        ];
    }

    /**
     * Creates a session in the User Component
     *
     * @param   AuthenticationUser  $user   The user to create a session for
     * @return  array                       The resulting session
     */
    private function createSession(AuthenticationUser $user): array
    {
        $expiry = new \DateTime('+15 minutes');
        $session = [
            'user'      => $user->getUserIdentifier(),
            'expiry'    => $expiry->format('Y-m-d H:i:s'),
            'valid'     => true,
        ];
        $session = $this->commonGroundService->createResource(
            $session, [
                'component' => 'uc',
                'type'      => 'sessions',
            ]
        );
        return $this->commonGroundService->updateResource(
            ['csrfToken' => $this->csrfTokenManager->getToken($session['id'])->getValue()],
            ['component' => 'uc', 'type' => 'sessions', 'id' => $session['id']]
        );
    }



    /**
     * Generates the JWT body
     *
     * @param AuthenticationUser    $user   The user for which the JWT has to be created
     * @return array                        The resulting JWT body as an array
     * @throws \Exception
     */
    private function generateJwtBody(AuthenticationUser $user): array
    {
        $time = new \DateTime();
        $session = $this->createSession($user);
        return [
            'user'      => $this->getUserArray($user),
            'roles'     => $user->getRoles(),
            'session'   => $session['id'],
            'csrfToken' => $session['csrfToken'],
            'iss'       => $this->parameterBag->get('app_url'),
            'ias'       => $time->getTimestamp(),
            'exp'       => date_timestamp_get(new \DateTime($session['expiry'])),
        ];
    }

    /**
     * Signs the JWT token
     *
     * @param   array   $payload    The payload to sign
     * @return  string              The resulting JWT token
     */
    public function generateToken(array $payload): string
    {
        $algorithmManger = new AlgorithmManager([new RS512()]);
        $jwk = JWKFactory::createFromKeyFile($this->parameterBag->get('app_key'));
        $jwsBuilder = new JWSBuilder($algorithmManger);
        $jws = $jwsBuilder
            ->create()
            ->withPayload(json_encode($payload))
            ->addSignature($jwk, ['alg' => 'RS512'])
            ->build();

        $serializer = new CompactSerializer();
        return $serializer->serialize($jws, 0);
    }

    /**
     * Generates a JWT token for a DigiD user
     *
     * @param   AuthenticationUser  $user   The user to generate a JWT for
     * @return  string                      The resulting JWT
     * @throws \Exception
     */
    public function generateJwtToken(AuthenticationUser $user): string
    {
        $payload = $this->generateJwtBody($user);
        return $this->generateToken($payload);
    }
}
