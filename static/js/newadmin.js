/* =========================================================================
 * newadmin.js (v1.3.6)
 * - Requires: jQuery, Bootstrap 5 bundle, DataTables (+ Buttons), JSZip, pdfmake
 * - ADMIN role passed from template: window.ADMIN_ROLE
 * ========================================================================= */

"use strict";

/* ===== Permissions ===== */
const CAN_EDIT = ["super", "limited"].includes(
  String(window.ADMIN_ROLE || "").trim().toLowerCase()
);

/* ===== State ===== */
let payload = { pending_users: [], approved_users: [], rejected_users: [] };
let currentStatus = "pending";
let dt = null;

/* ===== SweetAlert2 Toast (non-blocking notifications) ===== */
const Toast =
  window.Swal && Swal.mixin
    ? Swal.mixin({
        toast: true,
        position: "top-end",
        showConfirmButton: false,
        timer: 1800,
        timerProgressBar: true,
      })
    : { fire: () => {} };

/* ===== Utilities ===== */
function badge(s) {
  const map = { pending: "secondary", approved: "success", rejected: "danger" };
  return (
    '<span class="badge text-bg-' +
    (map[s] || "secondary") +
    ' text-uppercase">' +
    s +
    "</span>"
  );
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* Info button (not encoded email) */
function infoButton(u, status) {
  const companyVal = u.company || u.company_name || "—";
  return (
    '<button type="button" class="btn btn-sm btn-primary btn-icon info-btn" title="More info" ' +
    'data-email="' +
    esc(u.email) +
    '" data-phone="' +
    esc(u.phone || "—") +
    '" data-company="' +
    esc(companyVal) +
    '" data-device_name="' +
    esc(u.device_name || "—") +
    '" data-device_uuid="' +
    esc(u.device_uuid || "—") +
    '" data-registered="' +
    esc(u.registered_at || u.created_at || "—") +
    '" data-status="' +
    esc(status) +
    '">' +
    '<i class="fas fa-info"></i></button>'
  );
}

/* Row action buttons (email encoded for server endpoints) */
function actionButtons(u, status) {
  const emailEnc = encodeURIComponent(u.email || "");
  let html = infoButton(u, status);
  if (CAN_EDIT) {
    if (status === "pending") {
      html +=
        '<button type="button" class="btn btn-sm btn-success btn-icon approve-btn" data-email="' +
        emailEnc +
        '" title="Approve"><i class="fas fa-check"></i></button>';
      html +=
        '<button type="button" class="btn btn-sm btn-warning btn-icon reject-btn" data-email="' +
        emailEnc +
        '" title="Reject"><i class="fas fa-times"></i></button>';
    }
    html +=
      '<button type="button" class="btn btn-sm btn-danger btn-icon delete-btn" data-email="' +
      emailEnc +
      '" title="Delete"><i class="fas fa-trash"></i></button>';
  }
  return '<div class="actions-wrap">' + html + "</div>";
}

/* Map API payload to DataTables rows */
function toTableData(status) {
  const arr =
    status === "approved"
      ? payload.approved_users || []
      : status === "rejected"
      ? payload.rejected_users || []
      : payload.pending_users || [];
  return arr.map(function (u) {
    const companyVal = u.company || u.company_name || "—";
    return {
      email: u.email || "",
      phone: u.phone || "—",
      company: companyVal,
      device_uuid: u.device_uuid || "—",
      action_html: actionButtons(u, status),
    };
  });
}

/* ===== DataTable ===== */
function initTableOnce() {
  if (dt) return;
  if (!$.fn || !$.fn.DataTable) {
    console.error("DataTables is not loaded.");
    return;
  }
  dt = $("#usersTable").DataTable({
    autoWidth: false,
    dom: "lBtp",
    pageLength: 25,
    data: [],
    columns: [
      { data: "email", title: "Email" },
      { data: "phone", title: "Phone" },
      { data: "company", title: "Company", className: "d-none d-lg-table-cell" },
      {
        data: "device_uuid",
        title: "Device UUID",
        className: "d-none d-md-table-cell",
      },
      {
        data: "action_html",
        title: "Action",
        orderable: false,
        className: "text-center actions-cell",
      },
    ],
    buttons: [
      {
        extend: "excel",
        title: () => "users_" + currentStatus,
        exportOptions: { columns: ":visible:not(:last-child)" },
      },
      {
        extend: "pdf",
        title: () => "users_" + currentStatus,
        orientation: "landscape",
        pageSize: "A4",
        exportOptions: { columns: ":visible:not(:last-child)" },
      },
      {
        extend: "print",
        title: () => "Users - " + currentStatus.toUpperCase(),
        exportOptions: { columns: ":visible:not(:last-child)" },
      },
    ],
    initComplete: function () {
      const $len = $("#usersTable_length");
      if ($len.length) {
        const $slot = $("#toolbar .length-slot");
        if ($slot.length) {
          $len.find("label").appendTo($slot);
          $len.remove();
        }
      }
    },
  });
}

function redraw(status) {
  currentStatus = status || currentStatus;
  initTableOnce();
  if (!dt) return;
  dt.clear().rows.add(toTableData(currentStatus)).draw();
  const q = $("#globalSearch").val() || "";
  if (q) dt.search(q).draw();
}

function refreshCounts() {
  $("#countPending").text((payload.pending_users || []).length);
  $("#countApproved").text((payload.approved_users || []).length);
  $("#countRejected").text((payload.rejected_users || []).length);
}

function wireRefresh() {
  $("#refresh-btn")
    .off("click")
    .on("click", function (e) {
      e.preventDefault();
      fetchUsers();
    });
}

function fetchUsers() {
  $("#refresh-btn").prop("disabled", true).html('<i class="fas fa-spinner fa-spin"></i>');
  $.get("/newadmin_data")
    .done(function (data) {
      payload = {
        pending_users: data.pending_users || [],
        approved_users: data.approved_users || [],
        rejected_users: data.rejected_users || [],
      };
      refreshCounts();
      redraw(currentStatus);
    })
    .fail(function () {
      $("#notification")
        .text("Error loading user data.")
        .fadeIn()
        .delay(2500)
        .fadeOut();
    })
    .always(function () {
      $("#refresh-btn").prop("disabled", false).html('<i class="fas fa-sync-alt"></i>');
      wireRefresh();
    });
}

/* ===== Approve (simple POST) ===== */
$(document).on("click", ".approve-btn", function (e) {
  e.preventDefault();
  const emailEncoded = String($(this).data("email") || "");
  $.post("/newapprove/" + emailEncoded)
    .done(function () {
      Toast.fire({ icon: "success", title: "User approved" });
      fetchUsers();
    })
    .fail(function (xhr) {
      Swal.fire({
        icon: "error",
        title: "Approval failed",
        text: xhr.responseText || String(xhr.status),
      });
    });
});

/* ===== Confirm helper (Reject/Delete) — shows decoded email, posts encoded ===== */
function interceptConfirm(selector, options, postUrlBuilder) {
  document.addEventListener(
    "click",
    function (ev) {
      const el = ev.target.closest(selector);
      if (!el) return;

      ev.preventDefault();
      ev.stopImmediatePropagation(); // block any legacy handlers (e.g., confirm())

      const encodedEmail = String(el.getAttribute("data-email") || "");
      let displayEmail = encodedEmail;
      try {
        displayEmail = decodeURIComponent(encodedEmail);
      } catch (_) {
        /* ignore */
      }

      const opts = Object.assign(
        { showCancelButton: true }, // guarantee the Cancel button
        options,
        { text: displayEmail }
      );

      Swal.fire(opts).then((res) => {
        if (!res.isConfirmed) return;
        $.post(postUrlBuilder(encodedEmail))
          .done(function () {
            Toast.fire({
              icon: "success",
              title: options.successTitle || "Done",
            });
            fetchUsers();
          })
          .fail(function (xhr) {
            Swal.fire({
              icon: "error",
              title: options.failTitle || "Failed",
              text: xhr.responseText || String(xhr.status),
            });
          });
      });
    },
    true // capture phase
  );
}

/* Activate SweetAlert2 confirmations for Reject + Delete */
if (window.Swal) {
  interceptConfirm(
    ".reject-btn",
    {
      title: "Reject this user?",
      icon: "warning",
      confirmButtonText: "Yes, reject",
      cancelButtonText: "Cancel",
      successTitle: "User rejected",
      failTitle: "Rejection failed",
    },
    (email) => "/newreject/" + email
  );

  interceptConfirm(
    ".delete-btn",
    {
      title: "Delete this user?",
      icon: "error",
      confirmButtonText: "Yes, delete",
      cancelButtonText: "Cancel",
      successTitle: "User deleted",
      failTitle: "Delete failed",
    },
    (email) => "/newdelete_user/" + email
  );
}

/* ===== More Info modal ===== */
$(document).on("click", ".info-btn", function () {
  $("#m_email").text($(this).data("email") || "—");
  $("#m_phone").text($(this).data("phone") || "—");
  $("#m_company").text($(this).data("company") || "—");
  $("#m_device_name").text($(this).data("device_name") || "—");
  $("#m_device_uuid").text($(this).data("device_uuid") || "—");
  $("#m_registered_at").text($(this).data("registered") || "—");
  $("#m_status").html(badge($(this).data("status") || "pending"));
  new bootstrap.Modal(document.getElementById("deviceInfoModal")).show();
});

/* ===== Init ===== */
$(function () {
  // Export buttons
  $("#btnExcel").on("click", function () {
    if (dt) dt.button(0).trigger();
  });
  $("#btnPDF").on("click", function () {
    if (dt) dt.button(1).trigger();
  });
  $("#btnPrint").on("click", function () {
    if (dt) dt.button(2).trigger();
  });

  // Global search
  $("#globalSearch").on("input", function () {
    if (dt) dt.search(this.value).draw();
  });

  // Status tabs
  $("[data-status]").on("click", function () {
    $("[data-status]").removeClass("active");
    $(this).addClass("active");
    redraw($(this).data("status"));
  });

  wireRefresh();
  initTableOnce();
  fetchUsers();
});
