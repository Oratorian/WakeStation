// Global variables for encryption
let encryptionKey = null;
let encryptionStatus = {
    available: false,
    reason: null
};

// Encryption functions matching Python implementation
function loadEncryptionKey() {
    return new Promise((resolve, reject) => {
        if (encryptionKey) {
            resolve(encryptionKey);
            return;
        }

        $.ajax({
            type: 'GET',
            url: '/api/get_encryption_key',
            success: function(data) {
                if (data.success) {
                    encryptionKey = data.encryption_key;
                    encryptionStatus.available = true;
                    encryptionStatus.reason = null;
                    resolve(encryptionKey);
                } else {
                    encryptionStatus.available = false;
                    encryptionStatus.reason = 'Server failed to provide encryption key: ' + data.message;
                    reject(new Error(encryptionStatus.reason));
                }
            },
            error: function(xhr, status, error) {
                encryptionStatus.available = false;
                encryptionStatus.reason = 'Failed to fetch encryption key from server: ' + error;
                reject(new Error(encryptionStatus.reason));
            },
            dataType: 'json'
        });
    });
}

function encryptData(data) {
    if (!encryptionKey) {
        throw new Error('Encryption key not loaded');
    }

    // Convert base64 key to WordArray
    const keyBytes = CryptoJS.enc.Base64.parse(encryptionKey);

    // Generate random IV (16 bytes)
    const iv = CryptoJS.lib.WordArray.random(16);

    // Encrypt using AES-CBC with PKCS7 padding (CryptoJS default)
    const encrypted = CryptoJS.AES.encrypt(data, keyBytes, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    // Combine IV + encrypted data
    const combined = iv.concat(encrypted.ciphertext);

    // Return base64 encoded result (matching Python output)
    return combined.toString(CryptoJS.enc.Base64);
}

function showEncryptionWarning(reason) {
    $('#warning-reason').text(reason);
    $('#encryption-warning').show();
}

function hideEncryptionWarning() {
    $('#encryption-warning').hide();
}

// IP address validation function
function isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

// Edit IP address function
function editIP(mac, currentIP) {
    const newIP = prompt(`Enter new IP address for device with MAC ${mac}:`, currentIP);

    if (newIP === null) {
        return; // User cancelled
    }

    // Allow empty IP (to clear it)
    if (newIP !== '' && !isValidIP(newIP)) {
        showMessage('Invalid IP address format. Use format: 192.168.1.100', 'error');
        return;
    }

    $.ajax({
        type: 'POST',
        url: '/api/edit_ip',
        contentType: 'application/json',
        data: JSON.stringify({
            'mac': mac,
            'ip': newIP
        }),
        success: function(data) {
            if (data.success) {
                showMessage(data.message, 'success');
                load_pcs(); // Reload the PC list
            } else {
                showMessage(data.message, 'error');
            }
        },
        error: function(xhr, status, error) {
            console.log('Error updating IP:', status, error);
            showMessage('Failed to update IP address. Please try again.', 'error');
        },
        dataType: 'json'
    });
}

function checkEncryptionStatus() {
    // Check if CryptoJS is available
    if (typeof CryptoJS === 'undefined') {
        encryptionStatus.available = false;
        encryptionStatus.reason = 'CryptoJS library failed to load. Using server-side encryption instead.';
        reportEncryptionFailure(encryptionStatus.reason, 'cryptojs_missing');
        return;
    }

    // Check if encryption key is loaded
    if (!encryptionKey) {
        encryptionStatus.available = false;
        encryptionStatus.reason = 'Encryption key not available. Using server-side encryption instead.';
        reportEncryptionFailure(encryptionStatus.reason, 'key_unavailable');
        return;
    }

    encryptionStatus.available = true;
    encryptionStatus.reason = null;
}

function reportEncryptionFailure(reason, failureType) {
    $.ajax({
        type: 'POST',
        url: '/api/log_encryption_failure',
        contentType: 'application/json',
        data: JSON.stringify({
            'failure_reason': reason,
            'failure_type': failureType
        }),
        error: function() {
            console.warn('Failed to report encryption failure to server');
        }
    });
}

// Global AJAX error handler for 401 responses (invalid/expired tokens)
$(document).ajaxError(function(event, jqxhr, settings, thrownError) {
    if (jqxhr.status === 401) {
        console.log('Session expired or invalid. Redirecting to login...');
        // Clear any stored tokens/session
        document.cookie = 'access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        document.cookie = 'refresh_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        // Redirect to login
        window.location.href = '/ui/login';
    }
});

$(document).ready(function () {
    // Load encryption key on page load
    loadEncryptionKey().catch(function(error) {
        console.error('Failed to load encryption key:', error);
        showMessage('Failed to load encryption key', 'error');

        // Report encryption failure to server for logging
        reportEncryptionFailure(encryptionStatus.reason || error.message, 'key_loading');
    });

    // Initialize custom tabs
    $('.nav-tab').click(function() {
        const tabId = $(this).data('tab');

        // Update tab appearance
        $('.nav-tab').removeClass('active');
        $(this).addClass('active');

        // Show/hide content
        $('.tab-content').removeClass('active');
        $(`#${tabId}`).addClass('active');

        // Load content based on tab
        if (tabId === 'manage-users') {
            load_users();
        } else if (tabId === 'view-pcs') {
            load_pcs();
        }
    });

    // Initialize modal functionality
    $('.modal-close').click(function() {
        $('#shutdownModal').hide();
    });

    // Close modal when clicking on backdrop
    $('#shutdownModal').click(function(e) {
        if (e.target === this) {
            $(this).hide();
        }
    });

    // Bind logout button functionality
    $('#logout-button').click(function () {
        $.ajax({
            type: 'GET',
            url: '/ui/logout',
            success: function () {
                window.location.href = '/ui/login';
            },
            error: function (xhr, status, error) {
                console.log("Logout failed", "status:", status, "error:", error);
                // Even if logout fails, redirect to login
                window.location.href = '/ui/login';
            }
        });
    });

    // Create user form handler
    $('#create-user-form').submit(function (event) {
        event.preventDefault();
        const username = $('#username').val();
        const password = $('#password').val();
        const permission = $('#permission').val();

        $.ajax({
            type: 'POST',
            url: '/create_user',
            contentType: 'application/json',
            data: JSON.stringify({
                'username': username,
                'password': password,
                'permission': permission
            }),
            success: function (data) {
                if (data.success) {
                    showMessage('User created successfully', 'success');
                    $('#username').val('');
                    $('#password').val('');
                    $('#permission').val('user');
                    load_users();
                } else {
                    showMessage(data.message || data.error, 'error');
                }
            },
            error: function (xhr, status, error) {
                console.log("Error creating user", "status:", status, "error:", error);
                showMessage('Failed to create user. Please try again.', 'error');
            },
            dataType: 'json'
        });
    });

    $('#add-pc-form').submit(function (event) {
        event.preventDefault();
        const mac = $('#mac').val();
        const hostname = $('#hostname').val();
        const ip = $('#ip').val() || '';  // IP is optional

        // Validate MAC address format
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        if (!macRegex.test(mac)) {
            showMessage('Invalid MAC address format. Use format: AA:BB:CC:DD:EE:FF', 'error');
            return;
        }

        // Validate IP format if provided
        if (ip && !isValidIP(ip)) {
            showMessage('Invalid IP address format. Use format: 192.168.1.100', 'error');
            return;
        }

        const dataToSend = JSON.stringify({
            'mac': mac,
            'hostname': hostname,
            'ip': ip
        });
        $.ajax({
            type: 'POST',
            url: '/api/add',
            headers: {
                'Content-Type': 'application/json'
            },
            data: dataToSend,  // Send JSON string data
            success: function (data) {
                if (data.success) {
                    load_pcs(); // Reload the PC list after adding
                    showMessage(data.message, 'success');
                    $('#mac').val('');
                    $('#hostname').val('');
                    $('#ip').val('');
                } else {
                    showMessage(data.message, 'error');
                }
            },
            error: function (xhr, status, error) {
                console.log("Error adding PC", "status:", status, "error:", error);
                showMessage('Failed to add PC. Please try again.', 'error');
            },
            dataType: 'json'
        });
    });
});


load_pcs();

// Auto-refresh status every 30 seconds
setInterval(function() {
    if ($('#view-pcs').hasClass('active')) {
        refreshDeviceStatus();
    }
}, 10000);

// Function to refresh device status without reloading entire list
function refreshDeviceStatus() {
    $('.pc-card').each(function() {
        const card = $(this);
        const daemonGuid = card.data('daemon-guid');
        const statusDot = card.find('.pc-status');

        // Use IP for status checking if available
        const ip = card.find('.ip-display').text();

        // Skip status check if no IP is set
        if (!ip || ip === 'Not set') {
            statusDot.removeClass('online offline unknown no-ip').addClass('no-ip');
            return;
        }

        $.ajax({
            type: 'GET',
            url: '/api/status?ip=' + encodeURIComponent(ip),
            success: function(data) {
                if (data.success) {
                    statusDot.removeClass('online offline unknown').addClass(data.status);

                    // Update shutdown button state based on daemon availability
                    const shutdownBtn = card.find('.pc-actions button:nth-child(2)');
                    const daemonStatus = card.find('.daemon-status');

                    if (data.daemon_available) {
                        shutdownBtn.removeClass('btn-disabled').prop('disabled', false)
                                  .attr('title', 'Shutdown this device')
                                  .attr('onclick', `shutdown_pc('${daemonGuid}')`);
                        daemonStatus.removeClass('unavailable').text('Shutdown daemon available');
                    } else {
                        shutdownBtn.addClass('btn-disabled').prop('disabled', true)
                                  .attr('title', 'Shutdown daemon not detected')
                                  .removeAttr('onclick');
                        daemonStatus.addClass('unavailable').text('Shutdown daemon not detected');
                    }
                }
            },
            error: function() {
                statusDot.removeClass('online offline unknown').addClass('unknown');
            }
        });
    });
}

// Rediscover IPs for all devices
function rediscoverAllIPs() {
    if (confirm('Scan network for all device IP addresses? This may take a few seconds.')) {
        // Show loading state
        const button = $('#rediscover-btn');
        const originalText = button.text();
        button.prop('disabled', true).text('🔍 Scanning...');

        $.ajax({
            type: 'POST',
            url: '/api/rediscover_ips',
            contentType: 'application/json',
            success: function(data) {
                if (data.success) {
                    showMessage(data.message, 'success');
                    // Reload the devices list to show updated IPs
                    load_pcs();
                } else {
                    showMessage('Failed to rediscover IPs: ' + data.message, 'error');
                }
            },
            error: function(xhr, status, error) {
                showMessage('Error during IP rediscovery: ' + error, 'error');
            },
            complete: function() {
                // Restore button state
                button.prop('disabled', false).text(originalText);
            },
            dataType: 'json'
        });
    }
}

// Load PCs function
function load_pcs() {
    $.ajax({
        type: 'GET',
        url: '/api/load',
        beforeSend: function() {
        },
        success: function (data) {
            if (data.success) {
                if (data.pcs_list.length === 0) {
                    $('#pcs-list').html('');
                    $('#empty-devices').show();
                } else {
                    $('#empty-devices').hide();
                    $('#pcs-list').html(data.pcs_list.map(pc => {
                        const statusText = pc.status === 'no_ip' ? 'No IP Set' :
                                         pc.status === 'online' ? 'Online' :
                                         pc.status === 'offline' ? 'Offline' : 'Unknown';
                        const statusClass = pc.status === 'no_ip' ? 'no-ip' : pc.status || 'unknown';

                        return `
                        <div class="pc-card" data-daemon-guid="${pc.daemon_guid || ''}">
                            <div class="pc-status ${statusClass}"></div>
                            <div class="pc-info">
                                <h3 class="pc-hostname">${pc.hostname || 'Unknown'}</h3>
                                <div class="pc-details">
                                    <div>Status: ${statusText}</div>
                                    <div>IP: <span class="ip-display">${pc.ip || 'Not set'}</span>
                                        <button class="btn btn-tiny" onclick="editIP('${pc.mac}', '${pc.ip || ''}')" title="Edit IP Address" style="margin-left: 0.25rem; padding: 0.2rem;">
                                            <i class="material-icons-outlined" style="font-size: 0.9rem;">edit</i>
                                        </button>
                                    </div>
                                    <div>MAC: ${pc.mac || 'Unknown'}</div>
                                    <div class="daemon-guid-info" title="Daemon GUID: ${pc.daemon_guid || 'None'}">GUID: ${pc.daemon_guid ? pc.daemon_guid.substring(0, 8) + '...' : 'None'}</div>
                                </div>
                            </div>
                            <div class="pc-actions">
                                <button class="btn btn-small" onclick="wake_pc('${pc.mac}')">
                                    <i class="material-icons-outlined">power_settings_new</i>
                                    Wake
                                </button>
                                <button class="btn btn-small btn-secondary ${pc.daemon_available ? '' : 'btn-disabled'}"
                                        ${pc.daemon_available ? `onclick="shutdown_pc('${pc.daemon_guid}')"` : 'disabled'}
                                        title="${pc.daemon_available ? 'Shutdown this device' : 'Shutdown daemon not detected'}">
                                    <i class="material-icons-outlined">power_off</i>
                                    Shutdown
                                </button>
                                <button class="btn btn-small btn-danger" onclick="delete_pc('${pc.mac}')">
                                    <i class="material-icons-outlined">delete</i>
                                    Delete
                                </button>
                                <div class="daemon-status ${pc.daemon_available ? '' : 'unavailable'}">
                                    ${pc.daemon_available ? 'Shutdown daemon available' : 'Shutdown daemon not detected'}
                                </div>
                            </div>
                        </div>`;
                    }).join(''));
                }
            } else {
                showMessage(data.message, 'error');
            }
        },
        error: function (xhr, status, error) {
            console.log("Error loading PC list", "status:", status, "error:", error);
            console.log("Response text:", xhr.responseText);
            console.log("Status code:", xhr.status);
            showMessage('Failed to load PC list. Please try again.', 'error');
        },
        dataType: 'json'
    });
}

// Wake PC function
function wake_pc(mac) {
    $.ajax({
        type: 'POST',
        url: '/api/wake?mac=' + mac,
        success: function (data) {
            if (data.success) {
                showMessage(data.message, 'success');
            } else {
                showMessage(data.message, 'error');
            }
        },
        error: function (xhr, status, error) {
            console.log("Error sending wake-up signal", "status:", status, "error:", error);
            showMessage('Failed to send wake-up signal. Please try again.', 'error');
        },
        dataType: 'json'
    });
}

// Delete PC function
function delete_pc(mac) {
    $.ajax({
        type: 'GET',
        url: '/api/delete?mac=' + mac,
        success: function (data) {
            if (data.success) {
                load_pcs();
                showMessage(data.message, 'success');
            } else {
                showMessage(data.message, 'error');
            }
        },
        error: function (xhr, status, error) {
            console.log("Error deleting PC", "status:", status, "error:", error);
            showMessage('Failed to delete PC. Please try again.', 'error');
        },
        dataType: 'json'
    });
}

function shutdown_pc(daemon_guid) {
    $('#shutdownModal').show();

    // Check encryption status and show warning if needed
    checkEncryptionStatus();
    if (!encryptionStatus.available) {
        showEncryptionWarning(encryptionStatus.reason);
    } else {
        hideEncryptionWarning();
    }

    // Remove any existing click event listeners on the button
    $('#submitShutdown').off('click');

    // Add the click event listener
    $('#submitShutdown').on('click', function () {
        const username = document.getElementById('modal-username').value;
        const password = document.getElementById('modal-password').value;
        if (!username) {
            showMessage('Username is required for shutdown.', 'error');
            return;
        }
        if (!password) {
            showMessage('Password is required for shutdown.', 'error');
            return;
        }
        // Check if end-to-end encryption is available
        if (encryptionStatus.available) {
            try {
                // Create the JSON payload that matches Python format
                const shutdownPayload = JSON.stringify({
                    'username': username.strip ? username.strip() : username.trim(),
                    'password': password.strip ? password.strip() : password.trim(),
                    'action': 'shutdown'
                });

                // Encrypt the payload using the hardware key
                const encryptedPayload = encryptData(shutdownPayload);

                $.ajax({
                    type: 'POST',
                    url: '/api/shutdown',
                    contentType: 'application/json',
                    data: JSON.stringify({
                        'daemon_guid': daemon_guid,
                        'encrypted_payload': encryptedPayload
                    }),
            success: function (data) {
                if (data.success) {
                    showMessage(data.message, 'success');
                } else {
                    showMessage('Failed to send shutdown command: ' + data.message, 'error');
                }
            },
                    error: function (xhr, status, error) {
                        console.log("Shutdown command failed. Status:", status, "Error:", error, "Response:", xhr.responseText);
                        showMessage('Error: ' + error, 'error');
                    },
                    complete: function() {
                        $('#shutdownModal').hide();
                        load_pcs(); // Refresh device list to update button states
                    },
                    dataType: 'json'
                });
            } catch (encryptionError) {
                console.error('Client-side encryption failed:', encryptionError);
                encryptionStatus.available = false;
                encryptionStatus.reason = 'Client-side encryption failed: ' + encryptionError.message;
                showEncryptionWarning(encryptionStatus.reason);

                // Report the encryption failure
                reportEncryptionFailure(encryptionStatus.reason, 'encryption_failed');

                // Fall through to server-side encryption
                sendServerSideEncryption();
                return;
            }
        } else {
            // Fallback to server-side encryption
            sendServerSideEncryption();
        }

        function sendServerSideEncryption() {
            $.ajax({
                type: 'POST',
                url: '/api/shutdown',
                contentType: 'application/json',
                data: JSON.stringify({
                    'daemon_guid': daemon_guid,
                    'username': username,
                    'password': password,
                    'fallback_reason': encryptionStatus.reason
                }),
                success: function (data) {
                    if (data.success) {
                        showMessage(data.message, 'success');
                    } else {
                        showMessage('Failed to send shutdown command: ' + data.message, 'error');
                    }
                },
                error: function (xhr, status, error) {
                    console.log("Shutdown command failed. Status:", status, "Error:", error, "Response:", xhr.responseText);
                    showMessage('Error: ' + error, 'error');
                },
                complete: function() {
                    $('#shutdownModal').hide();
                    load_pcs(); // Refresh device list to update button states
                },
                dataType: 'json'
            });
        }
    });
}

// Load users function
function load_users() {
    $.ajax({
        type: 'GET',
        url: '/api/users',
        success: function (data) {
            if (data.success) {
                if (Object.keys(data.users).length === 0) {
                    $('#user-list').html('');
                    $('#empty-users').show();
                } else {
                    $('#empty-users').hide();
                    $('#user-list').empty();

                    Object.keys(data.users).forEach(function (username) {
                        const user = data.users[username];

                        const userItem = `
                        <div class="user-item">
                            <div class="user-info">
                                <div class="username">${user.username}</div>
                                <div class="permission ${user.permission}">${user.permission}</div>
                            </div>
                            <div class="user-actions">
                                <select class="select-field permission-select" data-username="${user.username}">
                                    <option value="user" ${user.permission === 'user' ? 'selected' : ''}>User</option>
                                    <option value="admin" ${user.permission === 'admin' ? 'selected' : ''}>Administrator</option>
                                </select>
                                <button class="btn btn-small change-permission-btn" data-username="${user.username}">
                                    <i class="material-icons-outlined">security</i>
                                    Update
                                </button>
                                <button class="btn btn-small btn-secondary change-password-btn" data-username="${user.username}">
                                    <i class="material-icons-outlined">lock</i>
                                    Reset Password
                                </button>
                                <button class="btn btn-small btn-danger delete-user-btn" data-username="${user.username}">
                                    <i class="material-icons-outlined">delete</i>
                                    Delete
                                </button>
                            </div>
                        </div>
                        `;

                        $('#user-list').append(userItem);
                    });
                }

                // Add event listeners for the dynamically added buttons
                $('.delete-user-btn').on('click', function () {
                    const username = $(this).data('username');
                    deleteUser(username);
                });

                $('.change-permission-btn').on('click', function () {
                    const username = $(this).data('username');
                    const newPermission = $(`select[data-username='${username}']`).val();
                    changeUserPermission(username, newPermission);
                });

                $('.change-password-btn').on('click', function () {
                    const username = $(this).data('username');
                    changeUserPassword(username);
                });
            } else {
                showMessage('Failed to load users.', 'error');
            }
        },
        error: function (xhr, status, error) {
            console.log("Error fetching users", "status:", status, "error:", error);
            showMessage('Failed to load users. Please try again.', 'error');
        },
        dataType: 'json'
    });
}

// Change user password function
function changeUserPassword(username) {
    const newPassword = prompt("Enter new password for " + username + ":");

    if (newPassword) {
        $.ajax({
            type: 'POST',
            url: '/api/change_password',
            contentType: 'application/json',
            data: JSON.stringify({ username: username, password: newPassword }),
            success: function (response) {
                if (response.success) {
                    showMessage('Password updated successfully', 'success');
                } else {
                    showMessage(response.message, 'error');
                }
            },
            error: function (xhr, status, error) {
                console.error("Error changing password", "status:", status, "error:", error);
                showMessage('Failed to change password. Please try again.', 'error');
            }
        });
    }
}

// Change user permission function
function changeUserPermission(username, newPermission) {
    if (newPermission) {
        $.ajax({
            type: 'POST',
            url: '/api/change_permission',
            contentType: 'application/json',
            data: JSON.stringify({ username: username, permission: newPermission }),
            success: function (response) {
                if (response.success) {
                    showMessage(response.message, 'success');
                    load_users();
                } else {
                    showMessage(response.message, 'error');
                }
            },
            error: function (xhr, status, error) {
                console.error("Error changing user permission", "status:", status, "error:", error);
                showMessage('Failed to change user permission. Please try again.', 'error');
            }
        });
    }
}

// Delete user function
function deleteUser(username) {
    if (confirm(`Are you sure you want to delete user ${username}?`)) {
        $.ajax({
            type: 'POST',
            url: '/api/delete_user',
            contentType: 'application/json',
            data: JSON.stringify({ username: username }),
            success: function (data) {
                if (data.success) {
                    showMessage('User deleted successfully', 'success');
                    load_users();
                } else {
                    showMessage(data.message, 'error');
                }
            },
            error: function (xhr, status, error) {
                console.log("Error deleting user", "status:", status, "error:", error);
                showMessage('Failed to delete user. Please try again.', 'error');
            },
            dataType: 'json'
        });
    }
}

// Modern message display function
function showMessage(message, type = 'info') {
    const messageEl = $('#message');
    const icons = {
        'success': 'check_circle',
        'error': 'error',
        'warning': 'warning',
        'info': 'info'
    };

    const colors = {
        'success': 'var(--success)',
        'error': 'var(--danger)',
        'warning': 'var(--warning)',
        'info': 'var(--accent-secondary)'
    };

    messageEl.html(`
        <i class="material-icons-outlined">${icons[type] || icons.info}</i>
        ${message}
    `);

    // Check if mobile view
    const isMobile = window.innerWidth <= 768;

    messageEl.css({
        'background': isMobile ?
            `rgba(${type === 'success' ? '16, 185, 129' : type === 'error' ? '239, 68, 68' : '0, 153, 255'}, 0.95)` :
            `rgba(${type === 'success' ? '16, 185, 129' : type === 'error' ? '239, 68, 68' : '0, 153, 255'}, 0.1)`,
        'color': isMobile ? '#ffffff' : colors[type] || colors.info,
        'border': `1px solid ${colors[type] || colors.info}`,
        'padding': '1rem',
        'border-radius': '8px',
        'display': 'flex',
        'align-items': 'center',
        'gap': '0.5rem',
        'font-weight': '500',
        'z-index': 9999
    });

    messageEl.show();

    setTimeout(() => {
        messageEl.fadeOut();
    }, 4000);
}

