<?php
/*
Name:     Rate Limit for posting
Purpose:  Block users that post too fast
Version:  2011-12-04
Author:   Andreas Gohr <andi@splitbrain.org>
*/
if (!defined('UNB_RUNNING')) die('Not a UNB environment in ' . basename(__FILE__));

// Define plug-in meta-data
UnbPluginMeta('Block users that post too fast');
UnbPluginMeta('Andreas Gohr <andi@splitbrain.org>', 'author');
UnbPluginMeta('en', 'lang');
UnbPluginMeta('unb.devel.20110527', 'version');
UnbPluginMeta('plugin_ratelimit_config', 'config');

if (!UnbPluginEnabled()) return;


function plugin_ratelimit_rc($opt,$default=null){
    $val = rc($opt);
    if($val !== false && $val !== null) return $val;
    return $default;
}

function plugin_ratelimit_config(&$data) {
    global $UNB;

    $groups = UnbGetGroupNames();

    // setup config fields
    if ($data['request'] == 'fields') {
        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'ratelimit_remove',
            'fieldvalue'  => plugin_stopforumspam_rc('ratelimit_remove',$groups[2]),
            'fieldlabel'  => 'ratelimit config remove label',
            'fielddesc'   => 'ratelimit config remove desc',
            'fieldsize'   => 10,
        );
        $data['fields'][] = array(
            'fieldtype'   => 'text',
            'fieldname'   => 'ratelimit_add',
            'fieldvalue'  => plugin_stopforumspam_rc('ratelimit_add',''),
            'fieldlabel'  => 'ratelimit config add label',
            'fielddesc'   => 'ratelimit config add desc',
            'fieldsize'   => 10,
        );
    }

    // save config data
    if ($data['request'] == 'handleform') {
        if(in_array($_POST['ratelimit_remove'],$groups)){
            $UNB['ConfigFile']['ratelimit_remove'] = $_POST['ratelimit_remove'];
        }else{
            $UNB['ConfigFile']['ratelimit_remove'] = '';
        }

        if(in_array($_POST['ratelimit_add'],$groups)){
            $UNB['ConfigFile']['ratelimit_add'] = $_POST['ratelimit_add'];
        }else{
            $UNB['ConfigFile']['ratelimit_add'] = '';
        }
    }

    return true;
}

function plugin_ratelimit_hook(&$data) {
    global $UNB;

    if($data['userid'] == 0) return; // we don't handle anonymous users

    // rate limits second => allowed posts
    $limits = array(
                5 => 0,
               30 => 4,
              300 => 10, // 5minutes
             1800 => 30, // 30 minutes
    );

    foreach($limits as $sec => $lim){
        $count = $UNB['Db']->FastQuery1st(
                    'Posts','COUNT(*)',
                    'User = '.intval($data['userid']).
                    ' AND (UNIX_TIMESTAMP() - '.$sec.') <= Date');
        if($count > $lim){
            UnbAddLog("ratelimit: user blocked for $count posts in $sec seconds");

            $groups = UnbGetGroupNames();
            $add    = plugin_ratelimit_rc('ratelimit_add','');
            $rem    = plugin_ratelimit_rc('ratelimit_remove','');
            $add    = array_search($add,$groups);
            $rem    = array_search($rem,$groups);

            if($rem) UnbRemoveUserFromGroup($data['userid'],$rem);
            if($add) UnbAddUserToGroup($data['userid'],$add);

            $data['error'] = 'You have been blocked from posting because you seem to be a spam bot. '.
                             'If you think this is wrong, contact an administrator.';
            return;
        }
    }
}

// Register hook functions
UnbRegisterHook('post.verifyaccept', 'plugin_ratelimit_hook');

