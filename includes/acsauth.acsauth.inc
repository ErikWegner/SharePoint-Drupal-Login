<?php

/**
 * @file
 * Provides functions used during ACS login processes.
 */


/**
 * Menu callback; The main page for processing OAuth login transactions.
 *
 * @param string $action
 *   The action being requested. Currently supports the following:
 *   - auth: Initiate ACS connection
 *   - callback: Complete ACS connection
 */
function acsauth_action_page($action_name) {
  if (user_is_logged_in()) {
    drupal_goto();
  }
  
  $app_id = variable_get('acsauth_id', '');
  $app_secret = variable_get('acsauth_secret', '');
  
  $error_message = t('The ACS login could not be completed due to an error. Please create an account or contact us directly. Details about this error have already been recorded to the error log.');
  
  if (!($app_id && $app_secret)) {
    watchdog('acsauth', 'An ACS login was attempted but could not be processed because the module is not yet configured. Visit the <a href="!url">ACS Auth configuration</a> to set up the module.', array(
      '!url' => url('admin/config/people/acsauth')
    ));
  }
  
  if ($action_name == 'auth') {
    if (isset($_REQUEST['SPHostUrl'])) {
      $callbackUrl = url('acsauth/callback', array(
        'absolute' => TRUE
      ));
      $appRedirectPath = "_layouts/15/appredirect.aspx";
      
      $appRedirectUrl = $_REQUEST['SPHostUrl'];
      if (substr($appRedirectUrl, -1) != '/') {
        $appRedirectUrl .= '/';
      }
      $appRedirectUrl .= $appRedirectPath;
      
      drupal_goto($appRedirectUrl, array(
        'query' => array(
          'response_type' => 'code',
          'redirect_uri' => $callbackUrl,
          'client_id' => $app_id
        )
      ));
    } else {
      watchdog('acsauth', 'An ACS login was attempted but no SPHostUrl parameter was in the query parameters.');
    }
  }
  
  if ($action_name == 'callback' && $_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['SPAppToken'] && $_POST['SPSiteUrl']) {
    module_load_include('php', 'acsauth', 'php-jwt/JWT');
    $token = $_POST['SPAppToken'];
    $spsiteurl = $_POST['SPSiteUrl'];
    
    // decode the context token to extract the info required by ACS
    $msg = JWT::decode($token, $app_secret, false);
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
    $querydata = http_build_query($postdata);
    
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
      $error_message = 'Unable to get the access token from ACS<br/>Error: ' . curl_error($ch);
    } else {
      curl_close($ch);
      unset($ch);
      unset($opts);
      
      // Get the access_token from the response
      $json = json_decode($result);
      $accToken = $json->{'access_token'};
      if (!$accToken) {
        $error_message = "No access token.";
        watchdog('acsauth', 'No access token:<br/>Response: ' . print_r($json, TRUE) . '<br/>Query: ' . print_r($querydata, TRUE));
      } else {
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
            if ($acsid < 1) {
              $error_message = 'User id not found in response.';
              watchdog('acsauth', 'User id not found in response.<pre>' . print_r($result, TRUE) . '</pre>');
            } else {
              $uid = acsauth_uid_load($acsid);
              if ($uid) {
                $fs = array(
                  'uid' => $uid
                );
                user_login_submit(array(), $fs);
                drupal_goto();
              } else {
                global $user;
                $user = acsauth_createuser_and_mapping($json);
                drupal_session_regenerate();
                drupal_goto();
              }
            }
          }
        }
      }
    }
  }
  
  // In the event of an error, we stay on this page.
  return $error_message;
}

/**
 * Create a new user account, save the ACS mapping
 */
function acsauth_createuser_and_mapping($spuserdata) {
  $username = $spuserdata->{'Title'};
  $query = "SELECT uid FROM {users} WHERE name = :name";
  $uid = db_query($query, array(
    ':name' => $username
  ))->fetchField();
  $i = 0;
  while ($uid) {
    $i++;
    $uid = db_query($query, array(
      ':name' => ($username . '_' . $i)
    ))->fetchField();
  }
  if ($i > 0) {
    $username = $username . '_' . $i;
  }
  
  //This will generate a random password, you could set your own here
  $password = user_password(8);
  $newuser = array(
    'name' => $username,
    'mail' => $spuserdata->{'Email'},
    'pass' => $password,
    'init' => 'email address',
    'status' => 1,
    'timezone' => variable_get('date_default_timezone'),
    'roles' => array(
      DRUPAL_AUTHENTICATED_RID => 'authenticated user'
    )
  );
  
  $account = user_save(NULL, $newuser);
  
  $id = db_insert('acsauth_users')->fields(array(
    'uid' => $account->uid,
    'acsid' => hexdec($spuserdata->{'UserId'}->{'NameId'})
  ))->execute();
  return $account;
}
