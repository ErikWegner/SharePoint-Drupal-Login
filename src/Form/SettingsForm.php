<?php

/**
 * @file
 * Contains \Drupal\acsauth\Form\SettingsForm.
 */

namespace Drupal\acsauth\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

class SettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'acsauth_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [
      'acsauth.settings',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $config = $this->config('acsauth.settings');

    $form['acsauth_id'] = array(
      '#type' => 'textfield',
      '#title' => t('App ID'),
      '#size' => 50,
      '#maxlengh' => 36,
      '#description' => t('To use ACS, a SharePoint Application must be created. Set up your app in https://your-sharepoint-server/_layouts/15/AppRegNew.aspx.') . ' ' . t('Enter your App ID here.'),
      '#default_value' => $config->get('acsauth_id')
    );

    $form['acsauth_secret'] = array(
      '#type' => 'textfield',
      '#title' => t('App Secret'),
      '#size' => 50,
      '#maxlengh' => 50,
      '#description' => t('To use ACS, a SharePoint Application must be created. Set up your app in https://your-sharepoint-server/_layouts/15/AppRegNew.aspx.') . ' ' . t('Enter your App Secret here.'),
      '#default_value' => $config->get('acsauth_secret')
    );

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $config = $this->config('acsauth.settings');
    $config->set('acsauth_id', $form_state->getValue('acsauth_id'));
    $config->set('acsauth_secret', $form_state->getValue('acsauth_secret'));
    $config->save();
    parent::submitForm($form, $form_state);
  }
}
