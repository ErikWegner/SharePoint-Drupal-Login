<?php

/**
 * @file
 * Contains \Drupal\acsauth\Controller\AuthenticationController.
 */

namespace Drupal\acsauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Url;
use Drupal\user\UserStorageInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Component\Utility\UrlHelper;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Route;
use Symfony\Component\DependencyInjection\ContainerInterface;

class AuthenticationController extends ControllerBase {

  /**
   * The logging service.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * User storage handler.
   *
   * @var \Drupal\user\UserStorageInterface
   */
  protected $userStorage;

  /**
   * Class constructor.
   */
  public function __construct(\Psr\Log\LoggerInterface $logger, UserStorageInterface $user_storage) {

    $this->logger = $logger;
    $this->userStorage = $user_storage;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    // Instantiates this controller class.
    return new static(
      // Load the service required to construct this class.
      $container->get('logger.channel.acsauth'),
      $container->get('entity.manager')->getStorage('user')
    );
  }

  public function content(string $action) {
    if (\Drupal::currentUser()->isAuthenticated()) {
      return $this->redirect('<front>');
    }
    $config = \Drupal::config('acsauth.settings');

    // Disable cache
    \Drupal::service('page_cache_kill_switch')->trigger();

    $error_message = t('The ACS login could not be completed due to an error. Please create an account or contact us directly. Details about this error have already been recorded to the error log.');

    $response = new Response($error_message, Response::HTTP_OK, ['Content-Type' => 'text/plain']);

    $app_id = $config->get('acsauth_id');
    $app_secret = $config->get('acsauth_secret');

    if (!($app_id && $app_secret)) {
      $this->logger->error('An ACS login was attempted but could not be processed because the module is not yet configured. Visit the <a href="!url">ACS Auth configuration</a> to set up the module.', array(
        '!url' => url('admin/config/people/acsauth')
      ));
    }

    if ($action == 'auth') {
      $response = $this->auth($response, $app_id);
    }

    if ($action == 'callback') {
      $response = $this->callback($response, $app_secret);
    }

    // Disable browser cache
    $response->setMaxAge(0);
    $response->setExpires();

    return $response;
  }

  protected function callback(Response $errorresponse, string $app_secret) {
    $this->logger->debug('Executing callback');
    if (!($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['SPAppToken'] && $_POST['SPSiteUrl'])) {
      $this->logger->error("The ACS callback was used with wrong parameters.");
      if (isset($_POST['SPRedirectMessage'])) {
        $this->logger->error("Error: @error", array('@error' => $_POST['SPRedirectMessage']));
      }
      return $errorresponse;
    }

    module_load_include('php', 'acsauth', 'php-jwt/JWT');
    $token = $_POST['SPAppToken'];
    $spsiteurl = $_POST['SPSiteUrl'];

    // decode the context token to extract the info required by ACS
    $msg = \JWT::decode($token, $app_secret, false);
    $oAuthSrv = $msg->appctx;
    $oAuthUrl = json_decode($oAuthSrv);
    $acs_server = $oAuthUrl->SecurityTokenServiceUri;

    $resources = str_replace('@', '/' . parse_url($spsiteurl, PHP_URL_HOST) . '@', $msg->appctxsender);

    // build the POST data as URLEncoded string
    $postdata = array(
      'grant_type' => 'refresh_token',
      'client_id' => $msg->aud,
      'client_secret' => $app_secret,
      'refresh_token' => $msg->refreshtoken,
      'resource' => $resources
    );
    $querydata = UrlHelper::buildQuery($postdata);

    // Add additional headers
    $opts = array(
      'Content-type: application/x-www-form-urlencoded',
      'Expect: 100-continue'
    );

    // Request the token from ACS (manually build the POST request)
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $acs_server);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $opts);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $querydata);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $result = curl_exec($ch);

    if (curl_errno($ch)) {
      $this->logger->error(
        'Unable to get the access token from ACS. Error: @curlerror', 
        array(
          '@curlerror' => curl_error($ch)
        )
      );
    } else {
      curl_close($ch);
      unset($ch);
      unset($opts);

      // Get the access_token from the response
      $json = json_decode($result);
      $this->logger->debug('Response: ' . print_r($json, TRUE) . '<br/>Query: ' . print_r($querydata, TRUE));
      if (!isset($json->access_token)) {
        $errorresponse->setContent("No access token.");
        if (isset($json->error)) {
          $this->logger->error(
            "Error: <p>@error</p><p>@description<p>",
            array(
              '@error' => $json->error,
              '@description' => $json->error_description
            ));
        }
        $this->logger->error('No access token:<br/>Response: ' . print_r($json, TRUE) . '<br/>Query: ' . print_r($querydata, TRUE));
      } else {
        $accToken = $json->{'access_token'};
        // Load user data
        $headers = array(
          'Accept: application/json;odata=verbose',
          'Authorization: Bearer ' . $accToken
        );

        $ch = curl_init($spsiteurl . '/_api/web/currentuser');
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_POST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $result = curl_exec($ch);

        if (curl_errno($ch)) {
          $error_message = 'Curl-Error: ' . curl_error($ch);
        } else {
          curl_close($ch);
          $json = json_decode($result);
          if (!isset($json->d)) {
            $error_message = "Response: " . check_plain(print_r($json, TRUE));
            if (isset($json->error) && isset($json->error->message) && isset($json->error->message->value)) {
              $error_message = "Response: " . $json->error->message->value;
            }
          } else {
            $json = $json->d;
            // Check if user already exists
            $acsid = hexdec($json->{'UserId'}->{'NameId'});
            $this->logger->debug('ACS user id @userid', array('@userid' => $acsid));
            if ($acsid < 1) {
              $this->logger->error('User id not found in response.<pre>' . print_r($result, TRUE) . '</pre>');
            } else {
              $this->logger->debug('Response:<pre>' . print_r($json, TRUE) . '</pre>');
              $user = $this->acsauth_createuser_and_mapping($json);
              if ($user) {
                user_login_finalize($user);
                return $this->redirect('<front>');
              }
            }
          }
        }
      }
    }

  // In the event of an error, we stay on this page.
  return $errorresponse;
  }

  protected function auth(Response $errorresponse, string $app_id) {
    if (!isset($_REQUEST['SPHostUrl'])) {
      $this->logger->error('An ACS login was attempted but no SPHostUrl parameter was in the query parameters.');
      return $errorresponse;
    }

    $callbackUrl = Url::fromUri('base:acsauth/callback');

    $appRedirectPath = "_layouts/15/appredirect.aspx";
    $appRedirectUrl = $_REQUEST['SPHostUrl'];

    if (substr($appRedirectUrl, -1) != '/') {
      $appRedirectUrl .= '/';
    }
    $appRedirectUrl .= $appRedirectPath;

    $urlWithParameters= Url::fromUri(
      $appRedirectUrl,
      array(
        'query' => array(
          'response_type' => 'code',
          'redirect_uri' => $callbackUrl->setAbsolute()->toString(),
          'client_id' => $app_id
        )
      )
    );

    return new TrustedRedirectResponse($urlWithParameters->toUriString());
  }

  protected function acsauth_createuser_and_mapping($spuserdata) {
    $acsid = hexdec($spuserdata->UserId->NameId);
    $uid = acsauth_uid_load($acsid);
    if ($uid !== FALSE) {
      $this->logger->info('ACS mapping found for user id @uid', array('@uid' => $uid));
      return \Drupal\user\Entity\User::load($uid);
    }

    $email = $spuserdata->Email;

    // Check if email is already taken
    $users = $this->userStorage->loadByProperties(array('mail' => $email));

    $user = NULL;
    if (count($users) == 0) {
      $username = $spuserdata->Title;
      $users = $this->userStorage->loadByProperties(array('name' => $username));
      $i = 0;
      while (count($users)) {
        $i++;
        $users = $this->userStorage->loadByProperties(array('name' => $username . '_' . $i));
      }
      if ($i > 0) {
        $username = $username . '_' . $i;
      }

      $this->logger->info('Creating new user account for user @username', array('@username' => $username));

      $language = \Drupal::languageManager()->getCurrentLanguage()->getId();
      $user = \Drupal\user\Entity\User::create();

      // Mandatory settings
      $user->setPassword( user_password());
      $user->enforceIsNew();
      $user->setEmail($email);
      $user->setUsername($username);

      $user->activate();

      // Save user
      $res = $user->save();
    }
    else {
      $this->logger->info('E-Mail already taken, linking user id @uid', array('@uid' => $uid));
      $user = array_values($users)[0];
    }

    // Save mapping
    $id = db_insert('acsauth_users')->fields(array(
      'uid' => $user->id(),
      'acsid' => $acsid
    ))->execute();

    $this->logger->debug('Mapping saved.');

    return $user;
  }
}
