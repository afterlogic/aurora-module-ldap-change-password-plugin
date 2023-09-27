<?php
/**
 * This code is licensed under AGPLv3 license or Afterlogic Software License
 * if commercial version of the product was purchased.
 * For full statements of the licenses see LICENSE-AFTERLOGIC and LICENSE-AGPL3 files.
 */

namespace Aurora\Modules\LdapChangePasswordPlugin;

use Aurora\System\SettingsProperty;

/**
 * @property bool $Disabled
 * @property array $SupportedServers
 * @property string $SearchDn
 * @property string $Host
 * @property int $Port
 * @property string $BindDn
 * @property string $BindPassword
 * @property string $HostBackup
 * @property int $PortBackup
 * @property string $PasswordType
 * @property string $SearchAttribute
 * @property string $PasswordAttribute
 */

class Settings extends \Aurora\System\Module\Settings
{
    protected function initDefaults()
    {
        $this->aContainer = [
            "Disabled" => new SettingsProperty(
                false,
                "bool",
                null,
                "Setting to true disables the module"
            ),
            "SupportedServers" => new SettingsProperty(
                ["*"],
                "array",
                null,
                "If IMAP Server value of the mailserver is in this list, password change is enabled for it. * enables it for all the servers."
            ),
            "SearchDn" => new SettingsProperty(
                "ou=users,dc=example,dc=org",
                "string",
                null,
                "Base Search DN for users lookup"
            ),
            "Host" => new SettingsProperty(
                "127.0.0.1",
                "string",
                null,
                "LDAP server host"
            ),
            "Port" => new SettingsProperty(
                389,
                "int",
                null,
                "LDAP server port"
            ),
            "BindDn" => new SettingsProperty(
                "cn=admin,dc=example,dc=org",
                "string",
                null,
                "Bind DN used for authentication"
            ),
            "BindPassword" => new SettingsProperty(
                "adminpassword",
                "string",
                null,
                "Password used for authentication on LDAP server. Will be automatically encrypted"
            ),
            "HostBackup" => new SettingsProperty(
                "Backup LDAP server host",
                "string",
                null,
                ""
            ),
            "PortBackup" => new SettingsProperty(
                389,
                "int",
                null,
                "Backup LDAP server port"
            ),
            "PasswordType" => new SettingsProperty(
                "md5",
                "string",
                null,
                "Password hashing type. Supported values: md5, crypt, or clear for no encryption"
            ),
            "SearchAttribute" => new SettingsProperty(
                "mail",
                "string",
                null,
                "LDAP field used for user lookup"
            ),
            "PasswordAttribute" => new SettingsProperty(
                "userPassword",
                "string",
                null,
                "LDAP field used for storing user password"
            ),
        ];
    }
}
