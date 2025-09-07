$(document).ready(function () {
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
            url: '/logout',
            success: function () {
                window.location.href = '/login';
            },
            error: function (xhr, status, error) {
                console.log("Logout failed", "status:", status, "error:", error);
                showMessage('Failed to log out. Please try again.', 'error');
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

        // Validate MAC address format
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        if (!macRegex.test(mac)) {
            showMessage('Invalid MAC address format. Use format: AA:BB:CC:DD:EE:FF', 'error');
            return;
        }
        const dataToSend = JSON.stringify({
            'mac': mac,
            'hostname': hostname
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
        const ip = card.find('.pc-details div:first').text().replace('IP: ', '');
        const statusDot = card.find('.pc-status');

        // Skip status check if IP is not resolved
        if (!ip || ip === 'Not resolved' || ip === '') {
            statusDot.removeClass('online offline unknown').addClass('unknown');
            return;
        }

        $.ajax({
            type: 'GET',
            url: '/api/status?ip=' + ip,
            success: function(data) {
                if (data.success) {
                    statusDot.removeClass('online offline unknown').addClass(data.status);

                    // Update shutdown button state based on daemon availability
                    const shutdownBtn = card.find('.pc-actions button:nth-child(2)');
                    const daemonStatus = card.find('.daemon-status');

                    if (data.daemon_available) {
                        shutdownBtn.removeClass('btn-disabled').prop('disabled', false)
                                  .attr('title', 'Shutdown this device');
                        daemonStatus.removeClass('unavailable').text('Shutdown daemon available');
                    } else {
                        shutdownBtn.addClass('btn-disabled').prop('disabled', true)
                                  .attr('title', 'Shutdown daemon not detected');
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

// Load PCs function
function load_pcs() {

    // Show loading indicator
    showDeviceLoadingMessage();

    $.ajax({
        type: 'GET',
        url: '/api/load',
        beforeSend: function() {
        },
        success: function (data) {
            hideDeviceLoadingMessage();
            if (data.success) {
                if (data.pcs_list.length === 0) {
                    $('#pcs-list').html('');
                    $('#empty-devices').show();
                } else {
                    $('#empty-devices').hide();
                    $('#pcs-list').html(data.pcs_list.map(pc => `
                        <div class="pc-card">
                            <div class="pc-status ${pc.status || 'unknown'}"></div>
                            <div class="pc-info">
                                <h3 class="pc-hostname">${pc.hostname || 'Unknown'}</h3>
                                <div class="pc-details">
                                    <div>IP: ${pc.ip || 'Not resolved'}</div>
                                    <div>MAC: ${pc.mac || 'Unknown'}</div>
                                </div>
                            </div>
                            <div class="pc-actions">
                                <button class="btn btn-small" onclick="wake_pc('${pc.mac}')">
                                    <i class="material-icons-outlined">power_settings_new</i>
                                    Wake
                                </button>
                                <button class="btn btn-small btn-secondary ${pc.daemon_available ? '' : 'btn-disabled'}"
                                        ${pc.daemon_available ? `onclick="shutdown_pc('${pc.ip}')"` : 'disabled'}
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
                        </div>
                    `).join(''));
                }
            } else {
                showMessage(data.message, 'error');
            }
        },
        error: function (xhr, status, error) {
            console.log("Error loading PC list", "status:", status, "error:", error);
            console.log("Response text:", xhr.responseText);
            console.log("Status code:", xhr.status);
            hideDeviceLoadingMessage();
            showMessage('Failed to load PC list. Please try again.', 'error');
        },
        dataType: 'json'
    });
}

// Wake PC function
function wake_pc(mac) {
    $.ajax({
        type: 'GET',
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

function shutdown_pc(ip) {
    $('#shutdownModal').show();

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
        $.ajax({
            type: 'POST',
            url: '/api/shutdown',
            contentType: 'application/json',
            data: JSON.stringify({
                'username': username,
                'pc_ip': ip,
                'password': password
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
            dataType: 'json'
        });
        $('#shutdownModal').hide();
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

// Device loading indicator with fake progress bar
function showDeviceLoadingMessage() {
    // Hide existing content
    $('#pcs-list').hide();
    $('#empty-devices').hide();

    // Show loading message with progress bar
    const loadingHtml = `
        <div id="device-loading" class="loading-container">
            <div class="loading-content">
                <div class="loading-spinner"></div>
                <h3>Detecting Device Status</h3>
                <p>Scanning network for devices...</p>
                <div class="progress-bar-container">
                    <div class="progress-bar" id="fake-progress"></div>
                </div>
                <div class="progress-text">
                    <span id="progress-stage">Initializing scan...</span>
                    <span id="progress-percent">0%</span>
                </div>
            </div>
        </div>
    `;

    // Insert loading indicator right after the "Network Devices" title, but before pcs-list
    $('#pcs-list').before(loadingHtml);

    // Start fake progress animation
    startFakeProgress();
}

function hideDeviceLoadingMessage() {
    $('#device-loading').remove();
    $('#pcs-list').show();
    // Stop any running progress intervals
    if (window.fakeProgressInterval) {
        clearInterval(window.fakeProgressInterval);
    }
}

function startFakeProgress() {
    let progress = 0;
    const stages = [
        "Initializing scan...",
        "Detecting network interfaces...",
        "Running ARP scan...",
        "Resolving device addresses...",
        "Checking daemon availability...",
        "Finalizing results..."
    ];
    let currentStage = 0;

    window.fakeProgressInterval = setInterval(() => {
        // Increment progress (faster at start, slower at end)
        if (progress < 30) {
            progress += Math.random() * 8 + 2; // 2-10% jumps
        } else if (progress < 70) {
            progress += Math.random() * 5 + 1; // 1-6% jumps
        } else if (progress < 90) {
            progress += Math.random() * 2 + 0.5; // 0.5-2.5% jumps
        } else {
            progress += Math.random() * 0.5; // Very slow near end
        }

        // Cap at 95% until real completion
        progress = Math.min(progress, 95);

        // Update progress bar
        $('#fake-progress').css('width', progress + '%');
        $('#progress-percent').text(Math.floor(progress) + '%');

        // Update stage text
        const targetStage = Math.floor((progress / 100) * stages.length);
        if (targetStage > currentStage && targetStage < stages.length) {
            currentStage = targetStage;
            $('#progress-stage').text(stages[currentStage]);
        }

        // If we've reached 95%, slow down the interval
        if (progress >= 95) {
            clearInterval(window.fakeProgressInterval);
            // Very slow trickle to 98%
            window.fakeProgressInterval = setInterval(() => {
                progress = Math.min(progress + 0.1, 98);
                $('#fake-progress').css('width', progress + '%');
                $('#progress-percent').text(Math.floor(progress) + '%');
            }, 500);
        }
    }, 150); // Update every 150ms
}