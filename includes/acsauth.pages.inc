<?php

/**
 * @file
 * Administrative pages and functions for ACS Auth module.
 */

/**
 * Menu callback; Display the settings form for Facebook OAuth.
 */
function acsauth_settings_form($form, &$form_state) {
  module_load_include('inc', 'acsauth', 'includes/acsauth.acsauth');
  
  $form['acsauth_id'] = array(
    '#type' => 'textfield',
    '#title' => t('App ID'),
    '#size' => 50,
    '#maxlengh' => 36,
    '#description' => t('To use ACS, a SharePoint Application must be created. Set up your app in https://your-sharepoint-server/_layouts/15/AppRegNew.aspx.') . ' ' . t('Enter your App ID here.'),
    '#default_value' => variable_get('acsauth_id', '')
  );
  $form['acsauth_secret'] = array(
    '#type' => 'textfield',
    '#title' => t('App Secret'),
    '#size' => 50,
    '#maxlengh' => 50,
    '#description' => t('To use ACS, a SharePoint Application must be created. Set up your app in https://your-sharepoint-server/_layouts/15/AppRegNew.aspx.') . ' ' . t('Enter your App Secret here.'),
    '#default_value' => variable_get('acsauth_secret', '')
  );
  
  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save'),
    '#weight' => 100
  );
  
  return $form;
}

/**
 * Form validation function for acsauth_settings_form().
 */
function acsauth_settings_form_validate($form, &$form_state) {
  // Remove trailing spaces from keys.
  $form_state['values']['acsauth_id'] = trim($form_state['values']['acsauth_id']);
  $form_state['values']['acsauth_secret'] = trim($form_state['values']['acsauth_secret']);
  
  // Do some basic data input validation.
  // TODO: Test guid form
  /*  if (!is_numeric($form_state['values']['acsauth_id']) || strlen($form_state['values']['acsauth_id']) > 20) {
  form_error($form['acsauth_id'], t('The App ID must be an integer (usually 11 characters).'));
  }
  if (strlen($form_state['values']['acsauth_secret']) != 32) {
  form_error($form['acsauth_secret'], t('The App Secret does not appear to be valid. It is usually a 32 character hash.'));
  }*/
}

/**
 * Form submission function for acsauth_settings_form().
 */
function acsauth_settings_form_submit($form, &$form_state) {
  variable_set('acsauth_id', $form_state['values']['acsauth_id']);
  variable_set('acsauth_secret', $form_state['values']['acsauth_secret']);
  
  drupal_set_message(t('The configuration options have been saved.'));
}

/**
 * User settings page for ACS Auth.
 *
 * Note that currently this is not a form, it's just a normal page.
 */
function acsauth_user_form($account) {
  module_load_include('inc', 'acsauth', 'includes/acsauth.acsauth');
  return theme('acsauth_user_info', array(
    'account' => $account
  ));
}

/**
 * Provided themed information about the user's current ACS connection.
 */
function theme_acsauth_user_info($variables) {
  $account = $variables['account'];
  
  $acsid = acsauth_acsid_load($account->uid);
  $output = '';
  if ($acsid !== FALSE) {
    $output .= '<p>' . t('Your account is connected with ACS.') . '</p>';
  } else {
    $output .= '<p>' . t('Your account is not currently connected with ACS.') . '</p>';
  }
  
  return $output;
}
