// All javascript goes here
// This is structured so it can be sanely minified.

// onLoad for all pages
$(document).ready(
    function () {
        help.init();
        password.init();

        // Focus on the first input=text thing on the page, if any
        var first = $("input[type='text']:first");
        if (first.attr('disabled')) {
            var siblings = first = first.siblings();

            for (var i = 0; i < siblings.length; i++) {
                var wrappedSib = $(siblings[i]);

                if (!wrappedSib.attr('disabled') && wrappedSib.is("input[type='text']")) {
                    first = $(siblings[i]);
                    break;
                }
            }
        }

        first.focus();
    }
);

// Hold functions that are common across the entire site
var common = function () {
    return {
        // Make a best effort to bust us out of any frames on the client side
        bustFrames: function () {
            if (top != self) {
                top.location.replace(self.location.protocol + '//' + self.location.host);
            }
        }
    };
} ();

// Hold functions particular to the affiliate authentication/login process
var affiliate = function () {
    return {
        // Redirect the user using javascript so we can change top properly
        redirect: function (target) {
            top.location.replace(target);
        }
    };
} ();

// Hold functions for displaying in-page "help"
var help = function () {
    var findHelpOverlay = function (jText) {
        return $(jText).siblings('.form-help');
    };

    var bindHelpOverlayEvents = function (jText) {
        jText
            .bind("keydown contextmenu", function () { help.hideHelpOverlay($(this)); })

            .focus(function () { showHideHelpOverlay($(this), /* focus = */true); })

            .blur(function () { showHideHelpOverlay($(this)); })
            .each(function () { showHideHelpOverlay($(this)); });
    };

    // Take this function with a pinch of salt -- it depends a lot on browser support.
    // It's more of a "nice to have".
    function copyCss(source, target, what) {
        for (var i = 0; i < what.lenght; i++) {
            var prop = what[i];
            try {
                target.css(prop, source.css(prop));
            } catch (ex) {
                // we tried all we could
            }
        }
    }

    function showHideHelpOverlay(jText, focus) {

        // we can't check for layout correctness until the edit box is actually on screen
        if (!jText.is(":visible"))
            return;

        if (jText.val().length != 0) {
            // IE renders text differently at alpha=100 and with no filter at all, so we explicitly remove it
            jText.css("opacity", 1).css("filter", "").removeClass("edit-field-overlayed");
            return;
        } else {
            // make the help text lighter to give visual feedback when the input is now focused
            jText.css("opacity", focus ? .5 : .3);
            jText.addClass("edit-field-overlayed");
        }

        var actualOverlay = jText.prev(".actual-edit-overlay");

        if (actualOverlay.length == 0) {
            var helpText = findHelpOverlay(jText).text();

            actualOverlay = jText.clone().attr("class", "actual-edit-overlay").attr("name", null).attr("id", null).attr("disabled", "disabled").val(helpText).css({
                position: "absolute",
                backgroundColor: "white", // disabled: disabled causes a different color in most browsers
                color: "black",
                opacity: 1,
                width: jText.width() + 2,
                height: jText.height()
            });

            copyCss(jText, actualOverlay, ["font-family", "font-size", "line-height", "text-align"]);
            jText.css({
                zIndex: 1,
                position: "relative"
            });

            actualOverlay.insertBefore(jText);

            actualOverlay.css("margin-left", "0px");

            // layout correction for chrome/safari
            if ($.browser.webkit) {
                actualOverlay.css("margin-top", "2px");
            }
        }
    }

    return {
        hideHelpOverlay: function (jText) {
            jText.css("opacity", 1);
            jText.css("filter", "");
            jText.removeClass('edit-field-overlayed');
        },

        init: function () {
            var helpDivs = $('.form-help');
            helpDivs.hide();

            for (var i = 0; i < helpDivs.length; i++) {
                var input = $(helpDivs[i]).siblings('input');

                bindHelpOverlayEvents(input);
            }
        }
    };
} ();

// Hold functions related to client side password validation
var password = function () {
    var minPasswordLength = 8;

    var _hasLowerCase = /[a-z]/;
    var _hasUpperCase = /[A-Z]/;
    var _hasDigit = /\d/;
    var _hasNonWord = /(_|[^\w\d])/;

    var password = [];
    var password2 = [];

    var email = [];
    var vanity = [];

    var error = $('<tr><td></td><td><div class="pw-error"></div></td></tr>');
    var error2 = $('<tr><td></td><td><div class="pw-error">Passwords do not match.</div></td></tr>');

    var enableForm = function () {
        $('input[type="submit"]').removeAttr('disabled');
    };

    // Enforces that password2 = password, and display an error message if it does not
    var mustMatch = function () {
        error2.detach();

        if (password.val().length == 0) { return; }

        if (password.val() != password2.val()) {
            password2.parents('tr').after(error2);

            return;
        }

        enableForm();
    };

    // Counts the # of unique characters in this password
    var uniqueCharacters = function (pw) {
        var hash = {};

        for (var i = 0; i < pw.length; i++)
            hash[pw[i]]++;

        var ret = 0;

        for (var p in hash) {
            if (hash.hasOwnProperty(p)) {
                ret++;
            }
        }

        return ret;
    };

    // Enforces server side password rules, inline on the client for convenience
    var enforceRules = function () {
        error.detach();

        var pw = password.val().toLowerCase();

        if (pw.length == 0) { return; }

        var hasLower = _hasLowerCase.test(password.val());
        var hasUpper = _hasUpperCase.test(password.val());
        var hasDigit = _hasDigit.test(password.val());
        var hasNonWord = _hasNonWord.test(password.val());
        var charClassCount = 0;

        if (hasLower) charClassCount++;
        if (hasUpper) charClassCount++;
        if (hasDigit) charClassCount++;
        if (hasNonWord) charClassCount++;

        if (charClassCount < 3) {
            var nag = 'Add';
            if (!hasUpper) nag += ' upper case,';
            if (!hasLower) nag += ' lower case,';
            if (!hasDigit) nag += ' numbers,';
            if (!hasNonWord) nag += ' special characters,';

            nag = nag.substr(0, nag.length - 1) + '.';

            nag = nag.replace(/(.*),/, '$1, or');

            error.find('.pw-error').text(nag);

            password.parents('tr').after(error);
            return;
        }

        if (email.length != 0 && email.val().length > 0 && (pw.indexOf(email.val().toLowerCase()) != -1 || email.val().toLowerCase().indexOf(pw) != -1)) {
            error.find('.pw-error').text('Cannot match your account name.');

            password.parents('tr').after(error);
            return;
        }

        if (vanity.length != 0 && vanity.val().length != 0 && (pw.indexOf(vanity.val().toLowerCase()) != -1 || vanity.val().toLowerCase().indexOf(pw) != -1)) {
            error.find('.pw-error').text('Cannot match your vanity identifier.');

            password.parents('tr').after(error);
            return;
        }

        var uniqueChars = uniqueCharacters(password.val());

        if (uniqueChars < minPasswordLength) {
            var remaining = minPasswordLength - uniqueChars;

            error.find('.pw-error').text('Must contain at least ' + remaining + ' more unique characters.');

            password.parents('tr').after(error);
            return;
        }

        // don't bother enforcing this until the password is actually *good*
        mustMatch();
    };

    return {
        // hook all password/password2 fields on a page
        init: function () {
            password = $('input[name="password"]');
            password2 = $('input[name="password2"]');

            email = $('input[name="email"]');
            vanity = $('input[name="vanity"]');

            if (password.length == 0 || password2.length == 0) return;

            password.keyup(enforceRules);
            password2.keyup(enforceRules);
            if (vanity.length != 0) vanity.blur(enforceRules);
        }
    };
} ();