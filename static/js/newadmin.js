
// newadmin_fixed.js

$(document).ready(function () {
    let table = $('#userTable').DataTable({
        dom: 'Bfrtip',
        buttons: [
            'copy', 'excel', 'pdf', 'print'
        ]
    });

    // Tabs switching
    $('.status-tab').on('click', function () {
        let status = $(this).data('status');
        $('.status-tab').removeClass('active');
        $(this).addClass('active');

        $('.status-tab .badge').removeClass('active-tab');
        $(this).find('.badge').addClass('active-tab');

        $.ajax({
            url: `/get_users/${status}`,
            method: 'GET',
            success: function (data) {
                table.clear().draw();
                data.users.forEach(function (user) {
                    let row = [
                        user.email,
                        user.phone || 'null',
                        user.device_name || 'null',
                        user.device_uuid || 'null',
                        `<button class="btn btn-sm btn-info view-btn" data-id="${user.id}">View</button>
                         <button class="btn btn-sm btn-success approve-btn" data-id="${user.id}">✔</button>
                         <button class="btn btn-sm btn-danger reject-btn" data-id="${user.id}">✖</button>
                         <button class="btn btn-sm btn-secondary delete-btn" data-id="${user.id}">🗑</button>`
                    ];
                    table.row.add(row).draw();
                });
            }
        });
    });

    // Approve user
    $('#userTable').on('click', '.approve-btn', function () {
        let userId = $(this).data('id');
        $.post(`/approve_user/${userId}`, function () {
            $('.status-tab.active').click();
        });
    });

    // Reject user
    $('#userTable').on('click', '.reject-btn', function () {
        let userId = $(this).data('id');
        $.post(`/reject_user/${userId}`, function () {
            $('.status-tab.active').click();
        });
    });

    // Delete user
    $('#userTable').on('click', '.delete-btn', function () {
        let userId = $(this).data('id');
        if (confirm("Are you sure you want to delete this user?")) {
            $.ajax({
                url: `/delete_user/${userId}`,
                method: 'DELETE',
                success: function () {
                    $('.status-tab.active').click();
                }
            });
        }
    });

    // Initial load
    $('.status-tab.active').click();
});
