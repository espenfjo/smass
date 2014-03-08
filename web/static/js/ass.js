var editable = false;

$(document).ready(function() {
    $('.btn-file :file').on('fileselect', function(event, numFiles, label) {
        var input = $(this).parents('.input-group').find(':text'),
            log = numFiles > 1 ? numFiles + ' files selected' : label;
        if( input.length ) {
            input.val(log);
        } else {
            if( log ) alert(log);
        }
    });

    var url = window.location;
    $('.navbar .nav').find('.active').removeClass('active');
    $('.navbar .nav li a').each(function () {
        if (this.href == url) {
            $(this).parent().addClass('active');
        }
    });
    setupListeners();
    setup_editables();

});
function setup_editables(){
    $.fn.editable.defaults.url = window.location.pathname;
    $.fn.editable.defaults.savenochange = true;
    $.fn.editable.defaults.send = "always";

    var csrftoken = getCookie('csrftoken');
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && sameOrigin(settings.url)) {
                // Send the token to same-origin, relative URLs only.
                // Send the token only if the method warrants CSRF protection
                // Using the CSRFToken value acquired earlier
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });
    $(".editable").each(function(){
        $(this).editable({"disabled":true});
    });
}
function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
function sameOrigin(url) {
    // test that a given url is a same-origin URL
    // url could be relative or scheme relative or absolute
    var host = document.location.host; // host + port
    var protocol = document.location.protocol;
    var sr_origin = '//' + host;
    var origin = protocol + sr_origin;
    // Allow absolute or scheme relative URLs to same origin
    return (url == origin || url.slice(0, origin.length + 1) == origin + '/') ||
        (url == sr_origin || url.slice(0, sr_origin.length + 1) == sr_origin + '/') ||
        // or any other URL that isn't scheme relative or absolute i.e relative.
        !(/^(\/\/|http:|https:).*/.test(url));
}
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = $.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function setupListeners() {
    $(".editable").on("click",function(event){
        event.preventDefault();
    });

    $(".tags").on('save', function(e, params) {

    });

    $('#enable').click(function() {
        $(".editable").each(function(){
            $(this).editable('toggleDisabled');
        });
        editable = !editable;

        if(editable){
            $('<a href="#" data-type="text" data-pk="1" data-title="Enter tag" id="empty-tag" class="editable editable-click tags"></a>').editable().appendTo(".tag-list");

            $('#empty-tag').on('save', function(e, params){
                var tag = $("#empty-tag");
                $(this).removeAttr('id');
                var new_html = '<span class="label label-primary">' + params.newValue +'</span>';
                tag.html(new_html);
                $('<a href="#" data-type="text" data-pk="1" data-title="Enter tag" id="empty-tag" class="editable editable-click tags"></a>').editable().appendTo(".tag-list");
            });
        } else {
            $('#empty-tag').remove()
        }



    });

    $('#modules a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    });

    $("#pe-toggler").click(function(){
        $(this).toggleClass('active, inactive');
    });

    $(document)
        .on('change', '.btn-file :file', function() {
            var input = $(this),
                numFiles = input.get(0).files ? input.get(0).files.length : 1,
                label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
            input.trigger('fileselect', [numFiles, label]);
        });
}
