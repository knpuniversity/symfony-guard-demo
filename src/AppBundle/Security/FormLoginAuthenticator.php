<?php

namespace AppBundle\Security;

use KnpU\Guard\Exception\CustomAuthenticationException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use KnpU\Guard\AbstractGuardAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class FormLoginAuthenticator extends AbstractGuardAuthenticator
{
    private $encoder;

    private $router;

    private $csrfTokenManager;

    public function __construct(UserPasswordEncoderInterface $encoder, RouterInterface $router, CsrfTokenManagerInterface $csrfTokenManager)
    {
        $this->encoder = $encoder;
        $this->router = $router;
        $this->csrfTokenManager = $csrfTokenManager;
    }

    public function getCredentials(Request $request)
    {
        if ($request->getPathInfo() != '/login_check' || !$request->isMethod('POST')) {
            return;
        }

        // optional - CSRF protection
        $csrfToken = $request->get('_csrf_token');
        $intention = 'authenticate'; // whatever value used in the template
        if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($intention, $csrfToken))) {
            throw new InvalidCsrfTokenException('Invalid CSRF token.');
        }

        $username = $request->request->get('_username');
        $request->getSession()->set(Security::LAST_USERNAME, $username);
        $password = $request->request->get('_password');

        if (!$password) {
            // totally optional - just showing off custom error messages!
            throw CustomAuthenticationException::createWithSafeMessage(
                // this could also be a translation key - you print this in login.html.twig
                'You should at least *try* entering a password'
            );
        }

        return array(
            'username' => $username,
            'password' => $password
        );
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try {
            $user = $userProvider->loadUserByUsername($credentials['username']);
        } catch (AuthenticationException $e) {
            // only needed if you want to customize the error message
            // otherwise, let loadUserByUsername() throw an exception, or return null
            throw CustomAuthenticationException::createWithSafeMessage(
                // this could also be a translation key - you print this in login.html.twig
                '"%username%" is a ridiculous username',
                array('%username%' => $credentials['username'])
            );
        }

        return $user;
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
