<?php
/**
 * This code is licensed under AGPLv3 license or AfterLogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\LdapChangePasswordPlugin;

use Aurora\Modules\Mail\Models\MailAccount;

/**
 * @license https://www.gnu.org/licenses/agpl-3.0.html AGPL-3.0
 * @license https://afterlogic.com/products/common-licensing AfterLogic Software License
 * @copyright Copyright (c) 2023, Afterlogic Corp.
 *
 * @property Settings $oModuleSettings
 *
 * @package Modules
 */
class Module extends \Aurora\System\Module\AbstractModule
{
    public function init()
    {
        $this->subscribeEvent('Mail::Account::ToResponseArray', array($this, 'onMailAccountToResponseArray'));
        $this->subscribeEvent('ChangeAccountPassword', array($this, 'onChangeAccountPassword'));
    }

    /**
     * @return Module
     */
    public static function getInstance()
    {
        return parent::getInstance();
    }

    /**
     * @return Module
     */
    public static function Decorator()
    {
        return parent::Decorator();
    }

    /**
     * @return Settings
     */
    public function getModuleSettings()
    {
        return $this->oModuleSettings;
    }

    /**
     * @param \Aurora\Modules\Mail\Models\MailAccount $oAccount
     * @param string $sDn
     * @param string $sPassword
     * @return \Aurora\System\Utils\Ldap|bool
     */
    protected function getLdap($oAccount, $sDn, $sPassword)
    {
        if (!$oAccount) {
            return false;
        }

        $oLdap = new \Aurora\System\Utils\Ldap((string)$this->oModuleSettings->SearchDn);
        return $oLdap->Connect(
            (string) $this->oModuleSettings->Host,
            (int) $this->oModuleSettings->Port,
            (string) $sDn,
            (string) $sPassword,
            (string) $this->oModuleSettings->HostBackup,
            (int) $this->oModuleSettings->PortBackup
        ) ? $oLdap : false;
    }

    protected function getPasswordHash($sPassword)
    {
        $sEncType = strtolower((string)  $this->oModuleSettings->PasswordType);

        $sPasswordHash = '';
        switch($sEncType) {
            case 'clear':
                $sPasswordHash = $sPassword;
                break;
            case 'md5':
                $sMd5Hash = md5($sPassword);
                for ($i = 0; $i < 32; $i += 2) {
                    $sPasswordHash .= chr(hexdec($sMd5Hash[ $i + 1 ]) + hexdec($sMd5Hash[ $i ]) * 16);
                }
                $sPasswordHash = '{MD5}' . base64_encode($sPasswordHash);
                break;
            case 'crypt':
            default:
                $sPasswordHash = '{CRYPT}' . password_hash($sPassword, PASSWORD_BCRYPT);
                break;
        }

        return $sPasswordHash;
    }

    /**
     * Adds to account response array information about if allowed to change the password for this account.
     * @param array $aArguments
     * @param mixed $mResult
     */
    public function onMailAccountToResponseArray($aArguments, &$mResult)
    {
        $oAccount = $aArguments['Account'];

        if ($oAccount && $this->checkCanChangePassword($oAccount)) {
            if (!isset($mResult['Extend']) || !is_array($mResult['Extend'])) {
                $mResult['Extend'] = [];
            }
            $mResult['Extend']['AllowChangePasswordOnMailServer'] = true;
        }
    }

    /**
     * Tries to change password for account.
     * @param \Aurora\Modules\Mail\Models\MailAccount $oAccount
     * @param string $sPassword
     * @return boolean
     * @throws \Aurora\System\Exceptions\ApiException
     */
    protected function changePassword($oAccount, $sPassword)
    {
        $bResult = false;
        if (0 < strlen($oAccount->getPassword()) && $oAccount->getPassword() !== $sPassword) {
            $sBindDn = $this->oModuleSettings->BindDn;
            $sBindPassword = $this->oModuleSettings->BindPassword;
            if ($sBindPassword && !\Aurora\System\Utils::IsEncryptedValue($sBindPassword)) {
                $this->setConfig('BindPassword', \Aurora\System\Utils::EncryptValue($sBindPassword));
                $this->saveModuleConfig();
            } else {
                $sBindPassword = \Aurora\System\Utils::DecryptValue($sBindPassword);
            }

            $oLdap = $this->getLdap($oAccount, $sBindDn, $sBindPassword);

            $sSearchAttribute = (string) $this->oModuleSettings->SearchAttribute;

            if ($oLdap) {
                if ($oLdap->Search('(' . $sSearchAttribute . '=' . $oAccount->Email . ')') && 1 === $oLdap->ResultCount()) {
                    $aData = $oLdap->ResultItem();
                    $sDn = !empty($aData['dn']) ? $aData['dn'] : '';

                    try {
                        if (!empty($sDn)) {
                            $aModifyEntry = array(
                                (string) $this->oModuleSettings->PasswordAttribute => $this->getPasswordHash($sPassword)
                            );
                            $oLdap->SetSearchDN('');
                            $oLdap->Modify($sDn, $aModifyEntry);
                            $bResult = true;
                        } else {
                            \Aurora\System\Api::Log('Can`t change password for user ' . $oAccount->Email . ' on LDAP-server');
                        }
                    } catch (\Exception $oException) {
                        $bResult = false;
                        \Aurora\System\Api::LogException($oException);
                    }
                } else {
                    $bResult = false;
                    \Aurora\System\Api::Log('Can`t find user ' . $oAccount->Email . ' on LDAP-server');
                }
            } else {
                \Aurora\System\Api::Log('Can`t connect to LDAP-server');
            }
        }

        return $bResult;
    }

    /**
     * Tries to change password for account if allowed.
     * @param array $aArguments
     * @param mixed $mResult
     */
    public function onChangeAccountPassword($aArguments, &$mResult)
    {
        $bPasswordChanged = false;
        $bBreakSubscriptions = false;

        $oAccount = $aArguments['Account'] instanceof MailAccount ? $aArguments['Account'] : false;
        if ($oAccount && $this->checkCanChangePassword($oAccount) && ($oAccount->getPassword() === $aArguments['CurrentPassword'])) {
            $bPasswordChanged = $this->changePassword($oAccount, $aArguments['NewPassword']);
            $bBreakSubscriptions = true; // break if Hmailserver plugin tries to change password in this account.
        }

        if (is_array($mResult)) {
            $mResult['AccountPasswordChanged'] = $mResult['AccountPasswordChanged'] || $bPasswordChanged;
        }

        return $bBreakSubscriptions;
    }

    /**
     * Checks if allowed to change password for account.
     * @param \Aurora\Modules\Mail\Models\MailAccount $oAccount
     * @return bool
     */
    protected function checkCanChangePassword($oAccount)
    {
        $bFound = in_array("*", $this->oModuleSettings->SupportedServers);

        if (!$bFound) {
            $oServer = $oAccount->getServer();

            if ($oServer && in_array($oServer->IncomingServer, $this->oModuleSettings->SupportedServers)) {
                $bFound = true;
            }
        }

        return $bFound;
    }
}
