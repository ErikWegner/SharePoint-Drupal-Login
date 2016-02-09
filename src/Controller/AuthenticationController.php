<?php

/**
 * @file
 * Contains \Drupal\acsauth\Controller\AuthenticationController.
 */

namespace Drupal\acsauth\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Access\AccessResult;
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
   * Class constructor.
   */
  public function __construct($logger) {

    $this->logger = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    // Instantiates this controller class.
    return new static(
      // Load the service required to construct this class.
      $container->get('logger.channel.acsauth')
    );
  }

  public function content($action) {
    if (\Drupal::currentUser()->isAuthenticated()) {
      return $this->redirect('<front>');
    }
    $config = \Drupal::config('acsauth.settings');

    // Disable cache
    \Drupal::service('page_cache_kill_switch')->trigger();

    $response = new Response($action, Response::HTTP_OK, ['Content-Type' => 'text/plain']);

    // Disable browser cache
    $response->setMaxAge(0);
    $response->setExpires();

    $app_id = $config->get('acsauth_id');
    $app_secret = $config->get('acsauth_secret');

    $error_message = t('The ACS login could not be completed due to an error. Please create an account or contact us directly. Details about this error have already been recorded to the error log.');

    if (!($app_id && $app_secret)) {
      $this->logger->error('acsauth', 'An ACS login was attempted but could not be processed because the module is not yet configured. Visit the <a href="!url">ACS Auth configuration</a> to set up the module.', array(
        '!url' => url('admin/config/people/acsauth')
      ));
    }

    return $response;
  }
}
