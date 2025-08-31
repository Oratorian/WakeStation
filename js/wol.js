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
        const ip = $('#ip').val();
        const hostname = $('#hostname').val();
        
        // Validate MAC address format
        const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
        if (!macRegex.test(mac)) {
            showMessage('Invalid MAC address format. Use format: AA:BB:CC:DD:EE:FF', 'error');
            return;
        }
        const dataToSend = JSON.stringify({
            'mac': mac,
            'ip': ip,
            'hostname': hostname
        });
        console.log("Data being sent:", dataToSend);  // Debugging log
        $.ajax({
            type: 'POST',
            url: '/api/add',
            headers: {
                'Authorization': 'Basic ' + btoa(sessionStorage.getItem('username') + ':' + sessionStorage.getItem('passwordHash')),
                'Content-Type': 'application/json'
            },
            data: dataToSend,  // Send JSON string data
            success: function (data) {
                if (data.success) {
                    console.log("PC added successfully", data);
                    load_pcs(); // Reload the PC list after adding
                    showMessage(data.message, 'success');
                    $('#mac').val('');
                    $('#ip').val('');
                    $('#hostname').val('');
                } else {
                    console.log("Failed to add PC", data);
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
}, 30000);

// Function to refresh device status without reloading entire list
function refreshDeviceStatus() {
    $('.pc-card').each(function() {
        const card = $(this);
        const ip = card.find('.pc-details div:first').text().replace('IP: ', '');
        const statusDot = card.find('.pc-status');
        
        $.ajax({
            type: 'GET',
            url: '/api/status?ip=' + ip,
            headers: {
                'Authorization': 'Basic ' + btoa(sessionStorage.getItem('username') + ':' + sessionStorage.getItem('passwordHash'))
            },
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
    $.ajax({
        type: 'GET',
        url: '/api/load',
        headers: {
            'Authorization': 'Basic ' + btoa(sessionStorage.getItem('username') + ':' + sessionStorage.getItem('passwordHash'))
        },
        success: function (data) {
            if (data.success) {
                console.log("PC list loaded successfully");
                if (data.pcs_list.length === 0) {
                    $('#pcs-list').html('');
                    $('#empty-devices').show();
                } else {
                    $('#empty-devices').hide();
                    $('#pcs-list').html(data.pcs_list.map(pc => `
                        <div class="pc-card">
                            <div class="pc-status ${pc.status || 'unknown'}"></div>
                            <div class="pc-info">
                                <h3 class="pc-hostname">${pc.hostname}</h3>
                                <div class="pc-details">
                                    <div>IP: ${pc.ip}</div>
                                    <div>MAC: ${pc.mac}</div>
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
                console.log("Failed to load PC list");
                showMessage(data.message, 'error');
            }
        },
        error: function (xhr, status, error) {
            console.log("Error loading PC list", "status:", status, "error:", error);
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
        headers: {
            'Authorization': 'Basic ' + btoa(sessionStorage.getItem('username') + ':' + sessionStorage.getItem('passwordHash'))
        },
        success: function (data) {
            if (data.success) {
                console.log("Wake-up signal sent successfully to", mac);
                showMessage(data.message, 'success');
            } else {
                console.log("Failed to send wake-up signal to", mac);
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
        headers: {
            'Authorization': 'Basic ' + btoa(sessionStorage.getItem('username') + ':' + sessionStorage.getItem('passwordHash'))
        },
        success: function (data) {
            if (data.success) {
                console.log("PC deleted successfully", mac);
                load_pcs();
                showMessage(data.message, 'success');
            } else {
                console.log("Failed to delete PC", mac);
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
                    console.log("Shutdown command successful");
                    showMessage(data.message, 'success');
                } else {
                    console.log("Shutdown command failed");
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
                console.log("Users loaded successfully.");
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
                console.log("Failed to load users:", data.message);
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