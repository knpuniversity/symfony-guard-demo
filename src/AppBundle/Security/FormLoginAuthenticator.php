<?php

namespace AppBundle\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use KnpU\Guard\AbstractGuardAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class FormLoginAuthenticator extends AbstractGuardAuthenticator
{
    private $encoder;

    private $router;

    public function __construct(UserPasswordEncoderInterface $encoder, RouterInterface $router)
    {
        $this->encoder = $encoder;
        $this->router = $router;
    }

    public function getCredentials(Request $request)
    {
        if ($request->getPathInfo() != '/login_check' || !$request->isMethod('POST')) {
            return;
        }

        $username = $request->request->get('_username');
        $password = $request->request->get('_password');

        return array(
            'username' => $username,
            'password' => $password
        );
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        return $userProvider->loadUserByUsername($credentials['username']);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        $plainPassword = $credentials['password'];
        if (!$this->encoder->isPasswordValid($user, $plainPassword)) {
            // throw any AuthenticationException
            throw new BadCredentialsException();
        }
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        $url = $this->router->generate('security_login_form');

        return new RedirectResponse($url);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // if the user hit a secure page and start() was called, this was
        // the URL they were on, and probably where you want to redirect to
        $targetPath = $request->getSession()->get('_security.'.$providerKey.'.target_path');

        if (!$targetPath) {
            $targetPath = $this->router->generate('homepage');
        }

        return new RedirectResponse($targetPath);
    }

    public function supportsRememberMe()
    {
        return true;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        $url = $this->router->generate('security_login_form');

        return new RedirectResponse($url);
    }
}
